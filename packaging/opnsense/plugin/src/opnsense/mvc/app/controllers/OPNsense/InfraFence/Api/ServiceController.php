<?php

namespace OPNsense\InfraFence\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/*
 * /api/infrafence/service/{start,stop,restart,status,reconfigure} from the
 * base class, plus register, mode, agentStatus, bans and log.
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\InfraFence\General';
    protected static $internalServiceTemplate = 'OPNsense/InfraFence';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'infrafence';

    /* Where register.php picks the install token up (root only, 0600). */
    const TOKEN_SPOOL = '/var/db/infrafence/register.token';

    private function backendJson($cmd, $params = [])
    {
        $backend = new Backend();
        $out = empty($params) ? $backend->configdRun($cmd) : $backend->configdpRun($cmd, $params);
        $data = json_decode(trim((string)$out), true);
        return is_array($data) ? $data : ['status' => 'error', 'message' => trim((string)$out)];
    }

    /* POST token=...: registers the agent once; the token is not stored. */
    public function registerAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $token = trim((string)$this->request->getPost('token'));
        if (!preg_match('#^[A-Za-z0-9_.:+/=\-]{8,512}$#', $token)) {
            return ['status' => 'error', 'message' => gettext('The install token is not valid.')];
        }
        $dir = dirname(self::TOKEN_SPOOL);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
            return ['status' => 'error', 'message' => gettext('Could not hand the token to the agent.')];
        }
        /* One registration at a time. */
        $lock = fopen($dir . '/register.lock', 'c');
        if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
            return ['status' => 'error', 'message' => gettext('A registration is already running.')];
        }
        $old = umask(0077);
        $tmp = tempnam($dir, 'reg');
        umask($old);
        $ok = $tmp !== false && chmod($tmp, 0600) &&
            file_put_contents($tmp, $token . "\n") === strlen($token) + 1 &&
            rename($tmp, self::TOKEN_SPOOL);
        if (!$ok) {
            if ($tmp !== false) {
                @unlink($tmp);
            }
            @unlink(self::TOKEN_SPOOL);
            flock($lock, LOCK_UN);
            fclose($lock);
            return ['status' => 'error', 'message' => gettext('Could not hand the token to the agent.')];
        }
        $result = $this->backendJson('infrafence register');
        @unlink(self::TOKEN_SPOOL);
        flock($lock, LOCK_UN);
        fclose($lock);
        return $result;
    }

    /* POST mode=protect|monitor: asks the dashboard to switch. */
    public function modeAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $mode = (string)$this->request->getPost('mode');
        if (!in_array($mode, ['protect', 'monitor'], true)) {
            return ['status' => 'error', 'message' => 'invalid mode'];
        }
        $user = preg_replace('/[^A-Za-z0-9_.@\-]/', '', (string)($_SESSION['Username'] ?? 'opnsense-gui'));
        if ($user === '' || strlen($user) > 64) {
            $user = 'opnsense-gui';
        }
        return $this->backendJson('infrafence mode', [$mode, $user]);
    }

    public function agentStatusAction()
    {
        return $this->backendJson('infrafence status');
    }

    public function bansAction()
    {
        $data = json_decode(trim((string)(new Backend())->configdRun('infrafence bans')), true);
        return ['rows' => is_array($data) ? $data : []];
    }

    public function logAction()
    {
        return ['log' => (string)(new Backend())->configdRun('infrafence log')];
    }
}
