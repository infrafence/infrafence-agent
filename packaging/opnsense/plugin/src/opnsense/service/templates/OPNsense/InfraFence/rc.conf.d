{# Copyright (c) 2026 ComCart S.r.l. SPDX-License-Identifier: BSD-2-Clause (see LICENSE). The InfraFence agent this plugin runs is licensed separately (BSL 1.1). #}
{% if helpers.exists('OPNsense.infrafence.general.enabled') and OPNsense.infrafence.general.enabled == '1' %}
infrafence_enable="YES"
{% else %}
infrafence_enable="NO"
{% endif %}
