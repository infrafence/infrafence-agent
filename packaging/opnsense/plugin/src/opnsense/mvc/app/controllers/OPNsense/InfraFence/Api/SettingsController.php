<?php

/*
 * Copyright (c) 2026 ComCart S.r.l. SPDX-License-Identifier: BSD-2-Clause (see LICENSE). The InfraFence agent this plugin runs is licensed separately (BSL 1.1).
 */

namespace OPNsense\InfraFence\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

/* GET /api/infrafence/settings/get, POST /api/infrafence/settings/set */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'general';
    protected static $internalModelClass = 'OPNsense\InfraFence\General';
}
