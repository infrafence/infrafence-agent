#!/bin/sh
# Runs inside the OpenWrt guest (test/router/boot.exp), one phase per call:
#   guest.sh install|after-reboot|uninstall TARGET
# Prints "CHECK <name> PASS|FAIL|SKIP [detail]" lines and a summary; the
# mock dashboard (test/distro/mockapi) and the package feed are on the
# QEMU host at 10.0.2.2:8080.
phase=$1
target=$2
API=http://10.0.2.2:8080
PASS=0
FAIL=0
FW=fw4
[ -x /sbin/fw4 ] || FW=fw3
PM=opkg
command -v apk >/dev/null 2>&1 && PM=apk

check() { # name ok(0/1) detail
	if [ "$2" = 0 ]; then echo "CHECK $1 PASS $3"; PASS=$((PASS + 1)); else echo "CHECK $1 FAIL $3"; FAIL=$((FAIL + 1)); fi
}
skip() { echo "CHECK $1 SKIP $2"; }
t() { # name command... : PASS when the command succeeds
	n=$1; shift
	if eval "$@" >/dev/null 2>&1; then check "$n" 0; else check "$n" 1 "($*)"; fi
}
waitfor() { # name seconds command... : PASS when the command succeeds within the time
	n=$1; s=$2; shift 2
	i=0
	while [ $i -lt "$s" ]; do
		if eval "$@" >/dev/null 2>&1; then check "$n" 0 "(${i}s)"; return 0; fi
		sleep 1; i=$((i + 1))
	done
	check "$n" 1 "(not within ${s}s: $*)"
	return 1
}
get() { wget -q -O - "$API$1"; }
post() { wget -q -O - --post-data="$2" "$API$1" >/dev/null; }
state() { get /state >/tmp/st.json; }
js() { state; jsonfilter -i /tmp/st.json -e "$1" 2>/dev/null; }
nevents() { js "@.events[@.type='$1']" | grep -c . ; }
inset() { # set address
	if [ $FW = fw4 ]; then nft list set inet infrafence "$1" 2>/dev/null | grep -q "[[:space:]{,]$2\([[:space:],}]\|\$\)"
	else ipset list "infrafence-$1" 2>/dev/null | grep -q "^$2\( \|$\)"; fi
}
fwpresent() {
	if [ $FW = fw4 ]; then nft list table inet infrafence >/dev/null 2>&1
	else iptables -w -C FORWARD -j INFRAFENCE_FWD 2>/dev/null && ipset -n list infrafence-ban4 >/dev/null 2>&1; fi
}
fwreload() { if [ $FW = fw4 ]; then fw4 reload; else /etc/init.d/firewall reload; fi; }
confdir() { sed -n 's/^conf-dir=\([^,]*\).*/\1/p' /var/etc/dnsmasq.conf.* 2>/dev/null | head -1; }
lanc() { ip netns exec lanc "$@"; }
pmremove() { if [ $PM = apk ]; then apk del "$@"; else opkg remove "$@"; fi; }
iso() { date -u -d "@$(( $(date +%s) + $1 ))" +%Y-%m-%dT%H:%M:%SZ; }

sync_json() { # monitor_mode extra-c2
	c2='{"ip":"203.0.113.10","source":"test-c2"}'
	[ -n "$2" ] && c2="$c2,{\"ip\":\"$2\",\"source\":\"test-c2\"}"
	cat <<EOF
{"config":{"monitor_mode":$1,"bf_threshold":5,"bf_window":60},
 "bans":[{"id":1,"ip_address":"203.0.113.7","expires_at":"$(iso 3600)"},{"id":2,"ip_address":"10.0.2.2"},{"id":3,"ip_address":"198.51.100.0/24"},{"id":4,"ip_address":"192.168.1.5"}],
 "threat_feed":[{"ip":null,"cidr":"192.0.2.0/24","source":"test"}],
 "rules":[{"id":7,"type":"block","protocol":"all","ip_address":"203.0.113.40","status":"pending","priority":1},{"id":8,"type":"block","protocol":"tcp","ip_address":"203.0.113.41","port":22,"status":"pending","priority":1}],
 "router":{"c2":[$c2],"domain_list":{"url":"/api/v1/agent/router/domains","etag":"v1","count":3},"share_device_names":false}}
EOF
}

client_setup() {
	# A LAN device: a network namespace on a veth port of br-lan.
	if ! command -v ip >/dev/null 2>&1 || ! ip netns list >/dev/null 2>&1 || ! modprobe veth 2>/dev/null; then
		if [ $PM = apk ]; then apk add ip-full kmod-veth >/dev/null 2>&1; else opkg update >/dev/null 2>&1; opkg install ip-full kmod-veth >/dev/null 2>&1; fi
	fi
	ip netns add lanc 2>/dev/null
	ip link add veth-r type veth peer name veth-c 2>/dev/null
	ip link set veth-c netns lanc
	ip link set veth-r master br-lan
	ip link set veth-r up
	lanc ip link set lo up
	lanc ip addr add 10.0.2.50/24 dev veth-c
	lanc ip link set veth-c up
	lanc ip route add default via 10.0.2.15
	sleep 2
	lanc ping -c 1 -W 2 10.0.2.15 >/dev/null 2>&1
}

echo "=== PHASE $phase on $target ($(. /etc/openwrt_release; echo "$DISTRIB_DESCRIPTION"), $PM, $FW, $(uname -m))"
case $phase in
install)
	free | head -2
	t dnsmasq_running pidof dnsmasq
	# Install through the installer from the signed test feed.
	wget -q -O /tmp/router.sh $API/feed/router-install.sh
	t installer_refuses_http "! sh /tmp/router.sh --feed $API/feed"
	INFRAFENCE_ALLOW_HTTP_FEED=1 sh /tmp/router.sh --feed $API/feed >/tmp/install.log 2>&1
	rc=$?
	cat /tmp/install.log
	check install_script "$rc"
	t binary_installed test -x /usr/sbin/infrafence-router
	t init_script test -x /etc/init.d/infrafence
	t uci_config uci -q get infrafence.main.enabled
	t keep_d grep -q /etc/infrafence/ /lib/upgrade/keep.d/infrafence
	t firewall_include "[ \"\$(uci -q get firewall.infrafence.path)\" = /usr/share/infrafence/firewall.include ]"
	if [ -d /www/luci-static ]; then
		t luci_view test -f /www/luci-static/resources/view/infrafence/status.js
		t luci_acl_json jsonfilter -i /usr/share/rpcd/acl.d/luci-app-infrafence.json -e @
	fi
	t not_running_unregistered "! pidof infrafence-router"
	# Short intervals for the test (never on a real router).
	sed -i 's/GOGC=50/GOGC=50 INFRAFENCE_TEST_FAST=1/' /etc/init.d/infrafence
	t register_https_only "! /usr/sbin/infrafence-router register --token test-install-token --server http://10.0.2.2:8080"
	INFRAFENCE_ALLOW_HTTP=1 /usr/sbin/infrafence-router register --token test-install-token --server $API
	check register $?
	t token_file_0600 "ls -l /etc/infrafence/config.json | grep -q '^-rw-------'"
	t token_not_in_uci "! uci show infrafence | grep -q distro-test-token"
	t register_kind "[ \"\$(js @.register_body.kind)\" = router ]"
	t register_capabilities "js @.register_body.capabilities | grep -q c2_detection"
	post /set-domains "$(printf 'c2.infrafence-test.net c2\nexample.org malware\nminer.infrafence-test.net miner\nbad..name\n')"
	post /set-sync "$(sync_json true)"
	/etc/init.d/infrafence restart
	waitfor agent_running 20 pidof infrafence-router
	waitfor heartbeat 30 "[ \"\$(js @.heartbeats)\" -ge 1 ]"
	t heartbeat_router_info "[ \"\$(js @.last_heartbeat.router_info.firewall)\" = $FW ]"
	t sync_kind_router "js @.sync_queries | grep -q kind=router"
	waitfor ban_applied 40 inset ban4 203.0.113.7
	t ban_cidr inset ban4 198.51.100.0/24
	t ban_gateway_refused "! inset ban4 10.0.2.2"
	t ban_private_refused "! inset ban4 192.168.1.5"
	t block_rule_applied inset ban4 203.0.113.40
	t feed_applied inset feed4 192.0.2.0/24
	t c2_applied inset c2v4 203.0.113.10
	waitfor rule_acks 30 "js @.rule_acks | grep -q failed"
	t rule_ack_applied "js @.rule_acks | grep -q '\"applied\"'"
	if [ $FW = fw4 ]; then
		t learning_no_drop "! nft list table inet infrafence | grep -q drop"
		t fw4_table_untouched "nft list table inet fw4 | grep -q 'chain forward'"
		nft list table inet infrafence | head -40
	else
		t learning_no_drop "! iptables -w -S INFRAFENCE_FWD | grep -q DROP"
		iptables -w -S | grep -i infrafence
	fi
	waitfor domain_list_loaded 40 "[ \"\$(jsonfilter -i /var/run/infrafence/status.json -e @.blocked_domains)\" = 3 ]"
	t learning_list_not_in_dnsmasq "! test -e \$(confdir)/infrafence-block.conf"
	if nslookup example.org 127.0.0.1 2>/dev/null | grep -q 'Address.*[0-9]\.[0-9]'; then internet=1; else internet=0; fi

	# LuCI's rpcd ACL: the page may read the status and run register,
	# nothing else (root has no password on a fresh image).
	if [ -d /www/luci-static ] && pidof uhttpd >/dev/null; then
		rpc() { wget -q -O - --post-data="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":[\"$1\",$2]}" http://127.0.0.1/ubus; }
		# An rpcd user granted only luci-app-infrafence (root has every right).
		uci -q batch <<-UCI
			add rpcd login
			set rpcd.@login[-1].username='ifrtest'
			set rpcd.@login[-1].password='$(uhttpd -m ifrtest-pass)'
			add_list rpcd.@login[-1].read='luci-app-infrafence'
			add_list rpcd.@login[-1].write='luci-app-infrafence'
			commit rpcd
		UCI
		/etc/init.d/rpcd restart; sleep 2
		sid=$(rpc 00000000000000000000000000000000 '"session","login",{"username":"ifrtest","password":"ifrtest-pass"}' | jsonfilter -e '@.result[1].ubus_rpc_session')
		if [ -n "$sid" ]; then
			# A session with only our ACL group, as LuCI grants it to the page.
			t acl_status_read "[ \"\$(rpc $sid '\"file\",\"read\",{\"path\":\"/var/run/infrafence/status.json\"}' | jsonfilter -e '@.result[0]')\" = 0 ]"
			t acl_token_write "[ \"\$(rpc $sid '\"file\",\"write\",{\"path\":\"/tmp/infrafence-enrol\",\"data\":\"not a token\",\"mode\":384}' | jsonfilter -e '@.result[0]')\" = 0 ]"
			t acl_register_allowed "[ \"\$(rpc $sid '\"file\",\"exec\",{\"command\":\"/usr/sbin/infrafence-router\",\"params\":[\"register\",\"--token-file\",\"/tmp/infrafence-enrol\"]}' | jsonfilter -e '@.result[0]')\" = 0 ]"
			t acl_token_file_consumed "! test -e /tmp/infrafence-enrol"
			t acl_register_argv_denied "[ \"\$(rpc $sid '\"file\",\"exec\",{\"command\":\"/usr/sbin/infrafence-router\",\"params\":[\"register\",\"--token-file\",\"/etc/infrafence/device-key\"]}' | jsonfilter -e '@.result[0]')\" != 0 ]"
			t acl_cleanup_denied "[ \"\$(rpc $sid '\"file\",\"exec\",{\"command\":\"/usr/sbin/infrafence-router\",\"params\":[\"cleanup\"]}' | jsonfilter -e '@.result[0]')\" != 0 ]"
			t acl_shell_denied "[ \"\$(rpc $sid '\"file\",\"exec\",{\"command\":\"/bin/sh\",\"params\":[\"-c\",\"id\"]}' | jsonfilter -e '@.result[0]')\" != 0 ]"
		else
			check luci_acl_login 1 "(rpcd login failed)"
		fi
	fi

	# A LAN device reaches a C2 address and looks up listed domains.
	client_setup
	check lan_client_up $?
	lanc wget -q -T 3 -O /dev/null http://203.0.113.10/ 2>/dev/null
	waitfor c2_hit_event 40 "[ \$(nevents lan_device_c2) -ge 1 ]"
	t c2_event_device "js \"@.events[@.type='lan_device_c2'].details.device_ip\" | grep -q 10.0.2.50"
	t c2_event_would_block "js \"@.events[@.type='lan_device_c2'].details.action\" | grep -q would_block"
	t c2_event_no_name "! js \"@.events[@.type='lan_device_c2'].details.device_name\" | grep -q ."
	echo "203.0.113.20 c2.infrafence-test.net" >>/etc/hosts
	killall -HUP dnsmasq
	sleep 1
	lanc nslookup c2.infrafence-test.net 10.0.2.15 >/dev/null 2>&1
	waitfor dns_c2_learned 20 inset c2v4 203.0.113.20
	waitfor blocked_domain_event 20 "[ \$(nevents blocked_domain) -ge 1 ]"
	lanc nslookup pool.miner.infrafence-test.net 10.0.2.15 >/dev/null 2>&1
	waitfor miner_dns_event 20 "js \"@.events[@.type='lan_device_miner'].details.detected_by\" | grep -q dns"
	lanc wget -q -T 3 -O /dev/null http://203.0.113.30:3333/ 2>/dev/null &
	waitfor miner_conntrack_event 40 "js \"@.events[@.type='lan_device_miner'].details.detected_by\" | grep -q conntrack"
	waitfor device_report 40 "js @.router_devices.devices | grep -q device_key"
	t device_report_no_names "[ -z \"\$(js '@.router_devices.devices[*].name')\" ] && [ \"\$(js @.router_devices.names_sent)\" = false ]"
	t device_report_key "js '@.router_devices.devices[*].device_key' | grep -q '^[0-9a-f]\{16\}\$'"

	# Full protection. /etc/hosts answers before local=: the Learning
	# test's entry goes first (dnsmasq re-reads it when the agent restarts
	# it to load the list).
	sed -i '/c2.infrafence-test.net/d' /etc/hosts
	post /set-sync "$(sync_json false 203.0.113.11)"
	if [ $FW = fw4 ]; then
		waitfor full_drop_rules 40 "nft list chain inet infrafence forward | grep -q 'c2v4.*drop'"
	else
		waitfor full_drop_rules 40 "iptables -w -S INFRAFENCE_FWD | grep -q 'c2v4 dst -j DROP'"
	fi
	waitfor full_list_in_dnsmasq 60 "test -e \$(confdir)/infrafence-block.conf"
	# The link appears before the agent restarted dnsmasq: wait for the
	# list to be in force (the canary answered NXDOMAIN).
	waitfor dns_list_in_force 40 "nslookup use-application-dns.net 127.0.0.1 2>&1 | grep -qi 'NXDOMAIN\|can.t find'"
	t dns_blocked_nxdomain "lanc nslookup c2.infrafence-test.net 10.0.2.15 2>&1 | grep -qi 'NXDOMAIN\|can.t find'"
	if [ $internet = 1 ]; then
		t dns_blocked_real_domain "nslookup example.org 127.0.0.1 2>&1 | grep -qi 'NXDOMAIN\|can.t find'"
	else
		skip dns_blocked_real_domain "no internet DNS from the guest"
	fi
	t dns_canary "nslookup use-application-dns.net 127.0.0.1 2>&1 | grep -qi 'NXDOMAIN\|can.t find'"
	t dns_other_domains "nslookup openwrt.org 127.0.0.1 >/dev/null 2>&1 || [ $internet = 0 ]"
	waitfor c2_full_applied 30 inset c2v4 203.0.113.11
	lanc wget -q -T 3 -O /dev/null http://203.0.113.11/ 2>/dev/null
	waitfor c2_blocked_event 40 "js \"@.events[@.type='lan_device_c2'].details.action\" | grep -q '^blocked'"

	# The firewall's own reload and someone flushing the ruleset.
	fwreload >/dev/null 2>&1
	sleep 3
	waitfor survives_fw_reload 20 "fwpresent && inset ban4 203.0.113.7"
	if [ $FW = fw4 ]; then
		t ban_timeout_kept "nft list set inet infrafence ban4 | grep '203.0.113.7' | grep -q expires"
		nft flush ruleset
	else
		iptables -w -D FORWARD -j INFRAFENCE_FWD; iptables -w -F INFRAFENCE_FWD
	fi
	waitfor watchdog_restores 30 "fwpresent && inset ban4 203.0.113.7"
	waitfor reset_event 30 "[ \$(nevents router_firewall_reset) -ge 1 ]"
	[ $FW = fw4 ] && /etc/init.d/firewall restart >/dev/null 2>&1 && sleep 3
	# procd restarts a crashed agent while the dashboard is down: the last
	# sync (tmpfs cache) stays in force, no fallback to empty Learning.
	get "/offline?on=1" >/dev/null
	kill -9 "$(pidof infrafence-router)"
	waitfor respawned_after_crash 40 pidof infrafence-router
	sleep 4
	t crash_keeps_bans "fwpresent && inset ban4 203.0.113.7 && inset c2v4 203.0.113.11"
	t crash_keeps_full "[ \"\$(jsonfilter -i /var/run/infrafence/status.json -e @.mode)\" = full ]"
	t crash_keeps_dns_list "test -e \$(confdir)/infrafence-block.conf && nslookup example.org 127.0.0.1 2>&1 | grep -qi 'NXDOMAIN\|can.t find' || [ $internet = 0 ]"
	get "/offline?on=0" >/dev/null
	pid=$(pidof infrafence-router)
	echo "agent RSS: $(grep VmRSS /proc/$pid/status)"
	echo "dnsmasq RSS: $(grep VmRSS /proc/$(pidof dnsmasq | cut -d' ' -f1)/status)"
	logread -e infrafence | tail -30
	;;
after-reboot)
	waitfor agent_started_on_boot 60 pidof infrafence-router
	hb=$(js @.heartbeats)
	waitfor heartbeats_after_reboot 30 "[ \$(js @.heartbeats) -gt $hb ]"
	waitfor table_after_reboot 60 "fwpresent && inset ban4 203.0.113.7"
	waitfor full_after_reboot 60 "[ \"\$(jsonfilter -i /var/run/infrafence/status.json -e @.mode)\" = full ]"
	waitfor list_after_reboot 90 "test -e \$(confdir)/infrafence-block.conf"
	t token_kept test -s /etc/infrafence/config.json
	pid=$(pidof infrafence-router)
	echo "agent RSS: $(grep VmRSS /proc/$pid/status)"
	/usr/sbin/infrafence-router status

	# The dashboard rate-limits the new endpoints (429 + Retry-After):
	# "later", never an error or a suspension.
	get "/ratelimit?path=/api/v1/agent/router-devices&on=1" >/dev/null
	get "/ratelimit?path=/api/v1/agent/router/domains&on=1" >/dev/null
	post /set-domains "$(printf 'c2.infrafence-test.net c2\nexample.org malware\nother.infrafence-test.net\n')"
	post /set-sync "$(sync_json false | sed 's/"etag":"v1","count":3/"etag":"v2","count":3/')"
	waitfor rate_limit_logged 40 "logread -e infrafence | grep -q 'rate limited by the dashboard'"
	hb=$(js @.heartbeats)
	waitfor heartbeats_during_429 20 "[ \$(js @.heartbeats) -gt $hb ]"
	t no_error_on_429 "[ -z \"\$(jsonfilter -i /var/run/infrafence/status.json -e @.error)\" ]"
	t not_suspended_on_429 "[ \"\$(js @.denied)\" = 0 ] && ! logread -e infrafence | grep -qi 'suspend\|refused the agent'"
	t list_kept_on_429 "test -e \$(confdir)/infrafence-block.conf"
	get "/ratelimit?path=/api/v1/agent/router-devices&on=0" >/dev/null
	get "/ratelimit?path=/api/v1/agent/router/domains&on=0" >/dev/null

	# A router without InfraFence Home: Learning, the domain endpoint
	# answers an empty list with ETag "not-included".
	post /set-domains "# InfraFence Home is not included"
	post /set-sync "$(sync_json true | sed 's/"etag":"v1","count":3/"etag":"\\"not-included\\"","count":0/')"
	waitfor home_free_learning 90 "[ \"\$(jsonfilter -i /var/run/infrafence/status.json -e @.mode)\" = learning ]"
	waitfor home_free_empty_list 120 "[ \"\$(jsonfilter -i /var/run/infrafence/status.json -e @.blocked_domains)\" = 0 ]"
	waitfor home_free_list_gone 60 "! test -e \$(confdir)/infrafence-block.conf"
	t home_free_no_error "! jsonfilter -i /var/run/infrafence/status.json -e @.error | grep -qi 'domain list'"
	t home_free_c2_kept inset c2v4 203.0.113.10
	t home_free_running pidof infrafence-router
	;;
uninstall)
	# Undo the test's edit: package managers keep a modified file of /etc.
	sed -i 's/ INFRAFENCE_TEST_FAST=1//' /etc/init.d/infrafence
	pkgs="infrafence-router infrafence-keyring"
	[ -f /www/luci-static/resources/view/infrafence/status.js ] && pkgs="luci-app-infrafence $pkgs"
	pmremove $pkgs
	check package_removed $?
	sleep 3
	t process_gone "! pidof infrafence-router"
	t binary_gone "! test -e /usr/sbin/infrafence-router"
	t firewall_clean "! fwpresent"
	if [ $FW = fw4 ]; then t fw4_intact "nft list table inet fw4 >/dev/null"; else t no_ipsets "! ipset -n list | grep -q infrafence"; fi
	t dnsmasq_list_gone "! test -e \$(confdir)/infrafence-block.conf"
	t dnsmasq_still_running pidof dnsmasq
	t include_removed "! uci -q get firewall.infrafence"
	t init_gone "! test -e /etc/init.d/infrafence"
	;;
esac
echo "RESULT target=$target phase=$phase pass=$PASS fail=$FAIL"
