{% if helpers.exists('OPNsense.infrafence.general.enabled') and OPNsense.infrafence.general.enabled == '1' %}
infrafence_enable="YES"
{% else %}
infrafence_enable="NO"
{% endif %}
