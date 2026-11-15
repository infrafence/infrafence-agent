<?php

namespace OPNsense\InfraFence;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm('general');
        $this->view->pick('OPNsense/InfraFence/index');
    }
}
