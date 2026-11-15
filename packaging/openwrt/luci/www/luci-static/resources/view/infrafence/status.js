'use strict';
'require view';
'require form';
'require fs';
'require ui';
'require poll';

// InfraFence router agent: enrolment, status, local settings. The
// protection mode (Learning / Full protection) is set in the dashboard.

var STATUS = '/var/run/infrafence/status.json';

function readStatus() {
	return L.resolveDefault(fs.read(STATUS), null).then(function(raw) {
		try { return raw ? JSON.parse(raw) : null; } catch (e) { return null; }
	});
}

function row(label, value) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td left', 'width': '33%' }, [ label ]),
		E('td', { 'class': 'td left' }, [ value ])
	]);
}

function renderStatus(st) {
	if (!st)
		return E('p', {}, [ _('The agent is not running. Enrol this router below, or check the log (logread -e infrafence).') ]);
	var mode = st.mode === 'full' ? _('Full protection') : _('Learning (detect and report, nothing blocked)');
	return E('table', { 'class': 'table' }, [
		row(_('Dashboard'), st.connected ? _('Connected') + ' (' + st.server + ')' : _('Not connected') + (st.error ? ': ' + st.error : '')),
		row(_('Mode'), mode + (st.synced ? '' : ' — ' + _('waiting for the first sync'))),
		row(_('Firewall'), st.firewall + ' / ' + st.firewall_backend),
		row(_('Blocked addresses'), String(st.bans + st.feed) + ' (' + _('C2 entries') + ': ' + st.c2 + ')'),
		row(_('Blocked domains'), String(st.blocked_domains) + (st.dns_blocking_active ? '' : ' — ' + _('not enforced'))),
		row(_('LAN devices'), String(st.lan_devices) + (st.flagged_devices ? ' — ' + st.flagged_devices + ' ' + _('flagged') : '')),
		row(_('Last sync'), st.last_sync || '-'),
		row(_('Version'), st.version)
	]);
}

return view.extend({
	load: function() {
		return readStatus();
	},

	render: function(st) {
		var statusNode = E('div', {}, [ renderStatus(st) ]);
		poll.add(function() {
			return readStatus().then(function(s) {
				statusNode.innerHTML = '';
				statusNode.appendChild(renderStatus(s));
			});
		}, 10);

		var token = E('input', { 'type': 'password', 'class': 'cbi-input-password', 'placeholder': _('Install token from the dashboard'), 'autocomplete': 'off' });
		var enrol = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, [ _('Enrol this router') ]),
			E('p', {}, [ _('In the InfraFence dashboard choose "Add router", copy the install token and paste it here.') ]),
			token, ' ',
			E('button', { 'class': 'btn cbi-button-action', 'click': ui.createHandlerFn(this, function() {
				var t = token.value.trim();
				if (!/^[A-Za-z0-9._~+\/=-]{8,512}$/.test(t)) {
					ui.addNotification(null, E('p', _('That does not look like an install token.')), 'warning');
					return;
				}
				// Through a file, never on the command line (visible in ps).
				// The agent deletes it once read.
				return fs.write('/tmp/infrafence-enrol', t + '\n', 384).then(function() {
					return fs.exec('/usr/sbin/infrafence-router', [ 'register', '--token-file', '/tmp/infrafence-enrol' ]);
				}).then(function(res) {
					token.value = '';
					if (res.code !== 0) {
						ui.addNotification(null, E('p', _('Enrolment failed: ') + (res.stderr || res.stdout || res.code)), 'error');
						return;
					}
					return fs.exec('/etc/init.d/infrafence', [ 'restart' ]).then(function() {
						ui.addNotification(null, E('p', _('Router enrolled. It starts in Learning mode; switch to Full protection from the dashboard.')), 'info');
					});
				});
			}) }, [ _('Enrol') ])
		]);

		var m = new form.Map('infrafence', _('InfraFence'), _('Protects the home network: blocks known attackers and malicious domains and spots infected devices.'));
		var s = m.section(form.NamedSection, 'main', 'agent', _('Settings on this router'));
		s.option(form.Flag, 'enabled', _('Enabled'));
		s.option(form.Flag, 'dns_capture', _('Watch DNS lookups for infected devices'), _('Read in the kernel, nothing is logged; only lookups of malicious domains are reported.'));
		s.option(form.Flag, 'dns_blocking', _('Block malicious domains (Full protection)'));
		var o = s.option(form.ListValue, 'device_names', _('Device names'), _('Names like "Laura\'s iPhone" are personal data. They are sent only if your organization enabled it in the dashboard.'));
		o.value('dashboard', _('As set in the dashboard'));
		o.value('never', _('Never send them'));

		return m.render().then(function(mapNode) {
			return E([], [
				E('h2', {}, [ _('InfraFence') ]),
				E('div', { 'class': 'cbi-section' }, [ E('h3', {}, [ _('Status') ]), statusNode ]),
				enrol,
				mapNode
			]);
		});
	}
});
