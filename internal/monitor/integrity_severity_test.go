package monitor

import "testing"

func TestFileSeverity(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/etc/sudoers", "critical"},
		{"/root/.ssh/authorized_keys", "critical"},
		{"/home/alice/.ssh/authorized_keys", "critical"},
		{"/etc/sudoers.d/webadmin", "critical"},
		{"/etc/ld.so.preload", "critical"},
		{"/etc/shadow", "warning"},
		{"/etc/ssh/sshd_config", "warning"},
		{"/etc/crontab", "warning"},
		{"/etc/cron.d/backup", "warning"},
		{"/var/spool/cron/crontabs/root", "warning"},
		{"/var/spool/cron/www-data", "warning"},
		{"/etc/systemd/system/updater.service", "warning"},
		{"/etc/systemd/system/updater.timer", "warning"},
		{"/etc/passwd", "info"},
		{"/etc/group", "info"},
		{"/etc/hosts", "info"},
		{"/etc/resolv.conf", "info"},
	}

	for _, c := range cases {
		if got := fileSeverity(c.path); got != c.want {
			t.Errorf("fileSeverity(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}
