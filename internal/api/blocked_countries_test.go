package api

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// The dashboard sends the union of the organization's and the server's
// countries in blocked_countries; keys the agent does not know are ignored.
func TestSyncBlockedCountriesIgnoresUnknownKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"config":{"blocked_countries":["XX","YY"],
			"blocked_countries_org":["XX"],"blocked_countries_server":["YY"]}}`))
	}))
	t.Cleanup(srv.Close)
	sync, err := New(srv.URL, "tok").Sync()
	if err != nil {
		t.Fatal(err)
	}
	if got := sync.Config.BlockedCountries; !reflect.DeepEqual(got, []string{"XX", "YY"}) {
		t.Fatalf("BlockedCountries = %v, want [XX YY]", got)
	}
}
