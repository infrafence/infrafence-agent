<?php

/*
 * Copyright (c) 2026 ComCart S.r.l. SPDX-License-Identifier: BSD-2-Clause (see LICENSE). The InfraFence agent this plugin runs is licensed separately (BSL 1.1).
 */

namespace OPNsense\InfraFence;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm('general');
        $this->view->pick('OPNsense/InfraFence/index');
    }
}
