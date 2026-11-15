<script>
    $(document).ready(function () {
        mapDataToFormUI({'frm_general': "/api/infrafence/settings/get"}).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });
        updateServiceControlUI('infrafence');

        function row(label, value) {
            return $("<tr/>").append($("<td/>").text(label)).append($("<td/>").text(value === undefined || value === null || value === "" ? "-" : value));
        }

        function refreshStatus() {
            ajaxGet("/api/infrafence/service/agentStatus", {}, function (d) {
                var a = d.appliance || {}, t = a.tables || {};
                var tb = $("#if_status").empty();
                tb.append(row("{{ lang._('Registered') }}", d.registered ? "{{ lang._('yes') }}" : "{{ lang._('no') }}"));
                tb.append(row("{{ lang._('Agent running') }}", d.running ? "{{ lang._('yes') }}" : "{{ lang._('no') }}"));
                tb.append(row("{{ lang._('Mode') }}", a.mode === "monitor" ? "{{ lang._('Learning') }}" : (a.mode === "protect" ? "{{ lang._('Full protection') }}" : "-")));
                tb.append(row("{{ lang._('Protection') }}", (a.protection || "-") + (a.protection_reason ? " (" + a.protection_reason + ")" : "")));
                tb.append(row("{{ lang._('Active bans') }}", t.active_bans));
                tb.append(row("{{ lang._('Last heartbeat') }}", d.last_heartbeat));
                tb.append(row("{{ lang._('Last sync') }}", d.last_sync_error ? d.last_sync_error : d.last_sync));
                tb.append(row("{{ lang._('Agent version') }}", d.version + (a.update_available ? " ({{ lang._('update available in System: Firmware') }}: " + a.update_available + ")" : "")));
                $("#if_mode_protect").toggle(a.mode === "monitor");
                $("#if_mode_monitor").toggle(a.mode === "protect");
                var fl = $("#if_findings").empty();
                (a.findings || []).forEach(function (f) {
                    fl.append($("<tr/>").append($("<td/>").text(f.severity)).append($("<td/>").text(f.title))
                        .append($("<td/>").text((f.detail || "") + (f.fix ? " " + f.fix : ""))));
                });
                if (!(a.findings || []).length) {
                    fl.append($("<tr/>").append($("<td colspan='3'/>").text("{{ lang._('No findings (checks run every 6 hours).') }}")));
                }
            });
        }
        refreshStatus();
        setInterval(refreshStatus, 15000);

        function showResult(r, ok) {
            if (r && r.status === "ok") {
                BootstrapDialog.show({type: BootstrapDialog.TYPE_SUCCESS, message: ok});
            } else {
                BootstrapDialog.show({type: BootstrapDialog.TYPE_WARNING, message: $("<div/>").text((r && r.message) ? r.message : "{{ lang._('Request failed') }}")});
            }
        }

        $("#saveAct").click(function () {
            saveFormToEndpoint("/api/infrafence/settings/set", 'frm_general', function () {
                ajaxCall("/api/infrafence/service/reconfigure", {}, function () {
                    updateServiceControlUI('infrafence');
                    refreshStatus();
                });
            });
        });

        $("#connectAct").click(function () {
            var token = $("#if_token").val();
            saveFormToEndpoint("/api/infrafence/settings/set", 'frm_general', function () {
                ajaxCall("/api/infrafence/service/register", {'token': token}, function (r) {
                    $("#if_token").val("");
                    showResult(r, "{{ lang._('Connected to InfraFence.') }}");
                    ajaxCall("/api/infrafence/service/reconfigure", {}, function () {
                        updateServiceControlUI('infrafence');
                        refreshStatus();
                    });
                });
            });
        });

        $(".if-mode").click(function () {
            var mode = $(this).data("mode");
            ajaxCall("/api/infrafence/service/mode", {'mode': mode}, function (r) {
                showResult(r, "{{ lang._('Requested: the agent applies it within a minute.') }}");
                refreshStatus();
            });
        });

        $("#tab_bans").click(function () {
            ajaxGet("/api/infrafence/service/bans", {}, function (d) {
                var tb = $("#if_bans").empty();
                (d.rows || []).forEach(function (b) {
                    tb.append($("<tr/>").append($("<td/>").text(b.ip)).append($("<td/>").text(b.reason || ""))
                        .append($("<td/>").text(b.source)).append($("<td/>").text(b.expires || "{{ lang._('until removed') }}")));
                });
            });
        });
        $("#tab_log").click(function () {
            ajaxGet("/api/infrafence/service/log", {}, function (d) { $("#if_log").text(d.log); });
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs">
    <li class="active"><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#status">{{ lang._('Status') }}</a></li>
    <li><a data-toggle="tab" href="#bans" id="tab_bans">{{ lang._('Bans') }}</a></li>
    <li><a data-toggle="tab" href="#logs" id="tab_log">{{ lang._('Log') }}</a></li>
</ul>
<div class="tab-content content-box">
    <div id="settings" class="tab-pane fade in active">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
        <div class="col-md-12">
            <hr/>
            <p>{{ lang._('Paste the install token from the InfraFence dashboard (Servers, Add server, OPNsense). It is used once to register this firewall and is not stored.') }}</p>
            <div class="form-inline">
                <input type="password" class="form-control" id="if_token" autocomplete="off" placeholder="{{ lang._('Install token') }}" style="width:420px"/>
                <button class="btn btn-primary" id="connectAct" type="button">{{ lang._('Save and connect') }}</button>
                <button class="btn btn-default" id="saveAct" type="button">{{ lang._('Save') }}</button>
            </div>
            <br/>
        </div>
    </div>
    <div id="status" class="tab-pane fade">
        <table class="table table-striped"><tbody id="if_status"></tbody></table>
        <div class="col-md-12">
            <button class="btn btn-primary if-mode" id="if_mode_protect" data-mode="protect" type="button" style="display:none">{{ lang._('Switch to Full protection') }}</button>
            <button class="btn btn-default if-mode" id="if_mode_monitor" data-mode="monitor" type="button" style="display:none">{{ lang._('Switch to Learning') }}</button>
        </div>
        <h3>{{ lang._('Configuration findings') }}</h3>
        <table class="table table-condensed"><tbody id="if_findings"></tbody></table>
    </div>
    <div id="bans" class="tab-pane fade">
        <table class="table table-condensed">
            <thead><tr><th>{{ lang._('Address') }}</th><th>{{ lang._('Reason') }}</th><th>{{ lang._('Source') }}</th><th>{{ lang._('Expires') }}</th></tr></thead>
            <tbody id="if_bans"></tbody>
        </table>
    </div>
    <div id="logs" class="tab-pane fade"><pre id="if_log" style="max-height:500px;overflow:auto"></pre></div>
</div>
