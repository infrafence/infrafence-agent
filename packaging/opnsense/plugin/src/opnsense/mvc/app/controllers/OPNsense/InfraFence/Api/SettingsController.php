<?php

namespace OPNsense\InfraFence\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

/* GET /api/infrafence/settings/get, POST /api/infrafence/settings/set */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'general';
    protected static $internalModelClass = 'OPNsense\InfraFence\General';
}
