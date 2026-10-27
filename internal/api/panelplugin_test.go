package api

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSyncPluginLatest(t *testing.T) {
	for _, c := range []struct {
		body string
		want map[string]string
	}{
		{`{"panel_plugin_latest":{"whm":"1.0.3"}}`, map[string]string{"whm": "1.0.3"}},
		{`{"panel_plugin_latest":{"whm":"1.0.3","plesk":"2.0.0"}}`, map[string]string{"whm": "1.0.3"}}, // not a reported plugin yet
		{`{}`, nil}, // older dashboards
		{`{"panel_plugin_latest":null}`, nil},
		{`{"panel_plugin_latest":{"whm":null}}`, nil},
		{`{"panel_plugin_latest":{"whm":103}}`, nil},
		{`{"panel_plugin_latest":{"whm":"1.0.3<script>"}}`, nil},
		{`{"panel_plugin_latest":{"whm":"latest"}}`, nil},
		{`{"panel_plugin_latest":"1.0.3"}`, nil},
		{`{"panel_plugin_latest":["1.0.3"]}`, nil},
	} {
		// A malformed value never fails the sync.
		var s SyncResponse
		if err := json.Unmarshal([]byte(c.body), &s); err != nil {
			t.Fatalf("%s: %v", c.body, err)
		}
		if got := s.PluginLatest(); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.body, got, c.want)
		}
	}
}

func TestValidPluginVersion(t *testing.T) {
	for _, v := range []string{"1.0.3", "10.20.30", "1.0.3-1", "1.0.3~rc1", "1.2.3.4"} {
		if !ValidPluginVersion(v) {
			t.Errorf("%q refused", v)
		}
	}
	for _, v := range []string{"", "1", "v1.0.3", "1.0.3 ", "1.0.3\n", "1..3", "1.0.3-" + strings.Repeat("a", 33), "1.0.3;rm", "1.0.3-<b>"} {
		if ValidPluginVersion(v) {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestHeartbeatPanelPlugin(t *testing.T) {
	b, _ := json.Marshal(HeartbeatRequest{PanelPlugin: &PanelPlugin{Panel: "whm", Version: "1.0.2"}})
	if !strings.Contains(string(b), `"panel_plugin":{"panel":"whm","version":"1.0.2"}`) {
		t.Errorf("with a plugin: %s", b)
	}
	b, _ = json.Marshal(HeartbeatRequest{})
	if !strings.Contains(string(b), `"panel_plugin":null`) {
		t.Errorf("without: %s", b)
	}
}
