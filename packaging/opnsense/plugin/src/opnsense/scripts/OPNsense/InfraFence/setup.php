#!/usr/local/bin/php
<?php

/*
 * Copyright (c) 2026 ComCart S.r.l. SPDX-License-Identifier: BSD-2-Clause (see LICENSE). The InfraFence agent this plugin runs is licensed separately (BSL 1.1).
 */

/*
 * install: create the External (advanced) aliases the rules reference.
 * OPNsense declares their pf tables and never fills or flushes them: the
 * agent does. uninstall: remove them (left in place when a user rule
 * still references one). Idempotent.
 */

require_once 'script/load_phalcon.php';

use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;

$names = [
    'infrafence_bans' => 'InfraFence: banned addresses (managed by the agent)',
    'infrafence_threat' => 'InfraFence: threat feed (managed by the agent)',
    'infrafence_geo' => 'InfraFence: blocked countries (managed by the agent)',
];
$action = $argv[1] ?? 'install';
$mdl = new Alias();
$changed = false;
foreach ($names as $name => $descr) {
    $existing = null;
    foreach ($mdl->aliases->alias->iterateItems() as $uuid => $a) {
        if ((string)$a->name === $name) {
            $existing = $uuid;
        }
    }
    if ($action === 'install' && $existing === null) {
        $node = $mdl->aliases->alias->Add();
        $node->name = $name;
        $node->type = 'external';
        $node->description = $descr;
        $node->enabled = '1';
        $changed = true;
    } elseif ($action === 'uninstall' && $existing !== null) {
        $mdl->aliases->alias->del($existing);
        $changed = true;
    }
}
if (!$changed) {
    exit(0);
}
$errors = $mdl->performValidation(false);
if ($errors->count() > 0) {
    foreach ($errors as $e) {
        echo "InfraFence aliases: " . $e->getMessage() . PHP_EOL;
    }
    exit(1);
}
$mdl->serializeToConfig();
Config::getInstance()->save();
