<?php

/*
 * Copyright (c) 2026 ComCart S.r.l. SPDX-License-Identifier: BSD-2-Clause (see LICENSE). The InfraFence agent this plugin runs is licensed separately (BSL 1.1).
 */

/*
 * os-infrafence plugin hooks. Function names start with the file name.
 * A PHP error here makes OPNsense skip the plugin (/tmp/PHP_errors.log).
 */

function infrafence_settings()
{
    global $config;
    $g = $config['OPNsense']['infrafence']['general'] ?? [];
    return is_array($g) ? $g : [];
}

function infrafence_enabled()
{
    return (infrafence_settings()['enabled'] ?? '0') == '1';
}

function infrafence_services()
{
    if (!infrafence_enabled()) {
        return [];
    }
    return [[
        'description' => gettext('InfraFence agent'),
        'configd' => [
            'restart' => ['infrafence restart'],
            'start' => ['infrafence start'],
            'stop' => ['infrafence stop'],
        ],
        'name' => 'infrafence',
        'pidfile' => '/var/run/infrafence.pid',
    ]];
}

/* daemon(8) tags the agent's output "infrafence": /var/log/infrafence/. */
function infrafence_syslog()
{
    return ['infrafence' => ['facility' => ['infrafence']]];
}

/*
 * Block rules in front of the user's rules (priority 1, as os-crowdsec),
 * per selected interface (WAN by default), for the three agent tables.
 * Block only: the plugin never adds a pass rule. They show as automatic
 * rules under Firewall > Rules and disappear with the plugin.
 */
function infrafence_firewall(\OPNsense\Firewall\Plugin $fw)
{
    if (!infrafence_enabled()) {
        return;
    }
    $s = infrafence_settings();
    $ifs = array_filter(explode(',', (string)($s['interfaces'] ?? '')));
    if (empty($ifs)) {
        $ifs = ['wan'];
    }
    $log = ($s['logblocks'] ?? '0') == '1';
    $tables = ['infrafence_bans', 'infrafence_threat', 'infrafence_geo'];
    foreach ($ifs as $if) {
        foreach ($tables as $table) {
            foreach (['inet', 'inet6'] as $proto) {
                $fw->registerFilterRule(1, [
                    'type' => 'block',
                    'interface' => $if,
                    'ipprotocol' => $proto,
                    'direction' => 'in',
                    'quick' => true,
                    'from' => '<' . $table . '>',
                    'log' => $log,
                    'descr' => 'InfraFence: block ' . $table,
                    '#ref' => 'ui/infrafence',
                ]);
            }
        }
    }
    if (($s['blockoutbound'] ?? '0') == '1') {
        /* Internal hosts may not reach banned or threat-feed addresses. */
        foreach (['infrafence_bans', 'infrafence_threat'] as $table) {
            foreach (['inet', 'inet6'] as $proto) {
                $fw->registerFilterRule(1, [
                    'type' => 'block',
                    'interface' => 'lan',
                    'ipprotocol' => $proto,
                    'direction' => 'in',
                    'quick' => true,
                    'to' => '<' . $table . '>',
                    'log' => $log,
                    'descr' => 'InfraFence: LAN to ' . $table,
                    '#ref' => 'ui/infrafence',
                ]);
            }
        }
    }
}
