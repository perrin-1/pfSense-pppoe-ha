<?php
/*
 * pppoe_ha_event.php - CARP handler with single-stage MASTER stabilize
 *
 * Devd usage:
 *   /usr/local/sbin/pppoe_ha_event carp <subsystem> <MASTER|BACKUP>
 *     <subsystem> may be "5@igb0", "carp1", or just "5"
 *
 * Manual:
 *   /usr/local/sbin/pppoe_ha_event reconcile [vhid]
 *   /usr/local/sbin/pppoe_ha_event reconcile_quiet [vhid]
 */

require_once("util.inc");
require_once("config.inc");
require_once("interfaces.inc");
require_once("/usr/local/pkg/pppoe_ha.inc");

/* ---- constants ---- */
const SUPPRESS_FILE        = '/var/run/pppoe_ha.suppress.json';
const STABILIZE_POLL_SEC   = 30;   // polling interval inside suppression
const SUPPRESS_WINDOW_SEC  = 120;  // upper bound for suppression window

/* ---- logging ---- */
function ha_log($msg, $prio = LOG_NOTICE) {
    static $opened = false;
    if (!$opened) {
        openlog('pppoe-ha', LOG_PID, LOG_USER);
        $opened = true;
        register_shutdown_function(function(){ closelog(); });
    }
    syslog($prio, $msg);
}
function ha_log_debug($msg) { ha_log($msg, LOG_DEBUG); }

/* ---- utils ---- */
function ppha_sanitize_token($s) {
    $s = trim((string)$s);
    if ($s !== '' && $s[0] === '$') { $s = substr($s, 1); }
    return $s;
}

/* Build target list from package rows and CARP VIPs */
function ppha_build_targets($only_vhid = null) {
    $rows = ppha_get_rows();
    $vips = config_get_path('virtualip/vip', []);
    $targets = [];

    if (!is_array($rows) || !is_array($vips)) { return []; }

    foreach ($rows as $i => $row) {
        $enabled = isset($row['enabled']) && strcasecmp((string)$row['enabled'], 'ON') === 0;
        $vipref  = array_key_exists('vipref', $row) ? (string)$row['vipref'] : '';
        $iface   = array_key_exists('iface',  $row) ? (string)$row['iface']  : '';
        if (!$enabled || $vipref === '' || $iface === '') { continue; }

        $vip = $vips[$vipref] ?? null;
        if (!$vip || ($vip['mode'] ?? '') !== 'carp') { continue; }

        $vhid = (int)($vip['vhid'] ?? -1);
        if ($vhid < 0) { continue; }
        if ($only_vhid !== null && (int)$only_vhid !== $vhid) { continue; }

        $real = get_real_interface($iface);
        if (empty($real)) {
            ha_log("row[$i] {$iface}/vipref={$vipref}: real interface not found; skip");
            continue;
        }

        $targets[] = [
            'idx'            => (int)$i,
            'iface_friendly' => $iface,   // e.g. wan
            'iface_real'     => $real,    // e.g. pppoe0
            'vipref'         => $vipref,
            'vhid'           => $vhid,
        ];
    }
    return $targets;
}

/* ---- CARP helpers ---- */
function parse_carp_subsystem($subsys) {
    $subsys = ppha_sanitize_token($subsys);
    if (preg_match('/^(\d+)\@([A-Za-z0-9_.:\-]+)$/', $subsys, $m)) {
        return ['vhid'=>(int)$m[1], 'real'=>$m[2], 'carpif'=>null];
    }
    if (preg_match('/^(carp\d+)$/', $subsys, $m)) {
        $carpif = $m[1];
        $out = []; @exec("/sbin/ifconfig ".escapeshellarg($carpif)." 2>/dev/null", $out);
        $vhid = null;
        foreach ($out as $line) {
            if (preg_match('/\bvhid\s+(\d+)/', $line, $mm)) { $vhid = (int)$mm[1]; break; }
        }
        return ['vhid'=>$vhid, 'real'=>null, 'carpif'=>$carpif];
    }
    if (preg_match('/^\d+$/', $subsys)) { return ['vhid'=>(int)$subsys, 'real'=>null, 'carpif'=>null]; }
    return ['vhid'=>null, 'real'=>null, 'carpif'=>null];
}

/* Read CARP state for VHID */
function get_carp_state_for_vhid($vhid) {
    $vhid = (int)$vhid;
    $out = []; $rc = 0;
    @exec('/sbin/ifconfig -a', $out, $rc);
    if ($rc !== 0 || empty($out)) { return null; }
    foreach ($out as $line) {
        if (preg_match('/\bcarp:\s*(MASTER|BACKUP|INIT)\b.*\bvhid\s+(\d+)/i', $line, $m)) {
            if ((int)$m[2] === $vhid) { return strtoupper($m[1]); }
        }
    }
    return null;
}

/* ---- PPPoE helpers ---- */
function is_pppoe_real($ifname){ return (bool)preg_match('/^pppoe\d+$/', (string)$ifname); }

function real_iface_present($real){
    $out = []; $rc = 0;
    @exec("/sbin/ifconfig " . escapeshellarg($real) . " 2>/dev/null", $out, $rc);
    return ($rc === 0 && !empty($out));
}

/* True if pppoe has v4 p2p or global v6 (not tentative) */
function get_pppoe_status($real) {
    $out = [];
    @exec("/sbin/ifconfig " . escapeshellarg($real) . " 2>&1", $out);
    $has_v4_p2p = false; $has_v6_global = false;
    foreach ($out as $line) {
        if (preg_match('/^\s*inet\s+\S+\s+-->\s+\S+/', $line)) { $has_v4_p2p = true; continue; }
        if (preg_match('/^\s*inet6\s+([0-9a-f:]+)/i', $line, $m)) {
            $addr = strtolower($m[1]);
            if (strpos($addr, 'fe80:') !== 0 && stripos($line, 'tentative') === false) { $has_v6_global = true; }
        }
    }
    return ['active'=>($has_v4_p2p || $has_v6_global), 'has_ipv4_p2p'=>$has_v4_p2p, 'has_v6_global'=>$has_v6_global];
}

/* pfSense-friendly up/down */
function iface_up($friendly){
    $cmd = "/usr/local/sbin/pfSctl -c " . escapeshellarg("interface reload {$friendly}");
    mwexec($cmd);
}
function iface_down($real){
    if (real_iface_present($real)) {
        mwexec("/sbin/ifconfig " . escapeshellarg($real) . " down");
    }
}

/* ---- suppression ---- */
function ppha_set_suppression(int $seconds, string $reason, int $vhid = 0) {
    $until = time() + max(1, $seconds);
    $data = ['until'=>$until, 'reason'=>$reason, 'vhid'=>$vhid];
    @file_put_contents(SUPPRESS_FILE, json_encode($data));
    ha_log("suppress on for {$seconds}s (reason={$reason}, vhid={$vhid})");
}
function ppha_clear_suppression() {
    if (file_exists(SUPPRESS_FILE)) { @unlink(SUPPRESS_FILE); ha_log("suppress cleared"); }
}
function ppha_is_suppressed() {
    if (!file_exists(SUPPRESS_FILE)) return false;
    $j = json_decode(@file_get_contents(SUPPRESS_FILE), true);
    if (!is_array($j) || empty($j['until'])) return false;
    if (time() >= (int)$j['until']) { @unlink(SUPPRESS_FILE); return false; }
    return true;
}

/* ---- background spawn ---- */
function spawn_bg(array $args) {
    $php  = PHP_BINARY ?: "/usr/local/bin/php";
    $self = escapeshellarg(realpath(__FILE__));
    $cmd  = $php . " -f " . $self . ' ' . implode(' ', array_map('escapeshellarg', $args)) . " >/dev/null 2>&1 &";
    mwexec($cmd);
}

/* ---- core actions ---- */
function ppha_apply_target_state(array $t, string $state) {
    $iface = $t['iface_friendly'];
    $real  = $t['iface_real'];
    $vhid  = $t['vhid'];

    switch ($state) {
        case 'MASTER':
            ha_log("VHID {$vhid} MASTER: bring up {$iface} ({$real})");
            if (real_iface_present($real)) {
                mwexec("/sbin/ifconfig " . escapeshellarg($real) . " up");
            } else {
                iface_up($iface);
            }
            ppha_set_suppression(SUPPRESS_WINDOW_SEC, 'master_stabilize', $vhid);
            spawn_bg(['MASTER_POST', (string)$vhid, $iface, $real]);
            break;

        case 'BACKUP':
            ha_log("VHID {$vhid} BACKUP: bring down {$real}");
            iface_down($real);
            break;

        default:
            ha_log("VHID {$vhid} {$state}: ignored");
    }
}

/* Reconcile for one VHID (quiet controls logging only) */
function reconcile_target(int $vhid, bool $quiet=false) {
    $targets = ppha_build_targets($vhid);
    if (!$targets) { if (!$quiet) ha_log("reconcile: no mappings for VHID {$vhid}"); return; }

    foreach ($targets as $t) {
        $iface = $t['iface_friendly'];
        $real  = $t['iface_real'];
        $state = get_carp_state_for_vhid($vhid) ?? 'INIT';

        if ($state === 'MASTER') {
            if (is_pppoe_real($real)) {
                $st = get_pppoe_status($real);
                if ($st['active']) {
                    if (!$quiet) ha_log("reconcile: MASTER and {$real} active - ok");
                    continue;
                }
            }
            if (!$quiet) ha_log("reconcile: MASTER ensure up {$iface}");
            iface_up($iface);
        } elseif ($state === 'BACKUP') {
            if (!$quiet) ha_log("reconcile: BACKUP ensure down {$real}");
            iface_down($real);
        } else {
            if (!$quiet) ha_log("reconcile: VHID {$vhid} state INIT - skip");
        }
    }
}

/* MASTER single-stage post: poll until state stable, then clear suppression */
function master_post_sequence(int $vhid, string $iface, string $real) {
    $deadline = time() + SUPPRESS_WINDOW_SEC;

    while (true) {
        if (time() >= $deadline) {
            ha_log("master_post: timeout reached, clearing suppression");
            ppha_clear_suppression();
            return;
        }

        $carp = get_carp_state_for_vhid($vhid);
        if ($carp !== 'MASTER') {
            ha_log("master_post: abort, became {$carp}");
            ppha_clear_suppression();
            return;
        }

        $ok = false;
        if (real_iface_present($real)) {
            $st = get_pppoe_status($real);
            $ok = $st['active'];
        }

        if ($ok) {
            ha_log("master_post: stable (MASTER + PPPoE up), clearing suppression");
            ppha_clear_suppression();
            return;
        }

        ha_log("master_post: not stable yet, reconcile and retry");
        reconcile_target($vhid, true);
        sleep(STABILIZE_POLL_SEC);
    }
}

/* ---- event wiring ---- */
function handle_carp_state_change($vhid, $state) {
    if (ppha_is_suppressed()) {
        ha_log("CARP event suppressed: VHID {$vhid} state={$state}");
        return;
    }
    $targets = ppha_build_targets($vhid);
    if (!$targets) { ha_log("no mappings for VHID {$vhid}; ignore"); return; }
    foreach ($targets as $t) { ppha_apply_target_state($t, $state); }
}

/* ---- main ---- */
function main_entry($argv) {
    array_shift($argv);
    $cmd = strtoupper($argv[0] ?? '');

    if ($cmd === 'CARP') {
        $subsys = ppha_sanitize_token($argv[1] ?? '');
        $state  = strtoupper(ppha_sanitize_token($argv[2] ?? ''));
        $info   = parse_carp_subsystem($subsys);
        $vhid   = $info['vhid'];

        ha_log("Handle CARP command for {$subsys} - {$state}");
        if ($vhid === null || !in_array($state, ['MASTER','BACKUP'], true)) {
            ha_log("Invalid CARP args: subsystem={$subsys} vhid=" . var_export($vhid,true) . " state={$state}");
            exit(1);
        }
        handle_carp_state_change($vhid, $state);
        exit(0);
    }

    if ($cmd === 'RECONCILE') {
        $vhid = (int)($argv[1] ?? 0);
        reconcile_target($vhid ?: 0, false);
        exit(0);
    }

    if ($cmd === 'RECONCILE_QUIET') {
        $vhid = (int)($argv[1] ?? 0);
        reconcile_target($vhid ?: 0, true);
        exit(0);
    }

    if ($cmd === 'MASTER_POST') {
        $vhid  = (int)($argv[1] ?? 0);
        $iface = (string)($argv[2] ?? '');
        $real  = (string)($argv[3] ?? '');
        if ($vhid <= 0 || $iface === '' || $real === '') { exit(1); }
        master_post_sequence($vhid, $iface, $real);
        exit(0);
    }

    echo "Usage:\n";
    echo "  pppoe_ha_event carp <vhid|carpX|vhid@realif> <MASTER|BACKUP>\n";
    echo "  pppoe_ha_event reconcile [vhid]\n";
    echo "  pppoe_ha_event reconcile_quiet [vhid]\n";
    exit(1);
}

main_entry($argv);
