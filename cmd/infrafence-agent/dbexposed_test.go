package main

import (
	"testing"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/watcher"
)

func TestCheckExposedDBPortsReportsChanges(t *testing.T) {
	list := []watcher.ExposedDBPort{{Port: 3306, Service: "MySQL/MariaDB", Warning: "MySQL/MariaDB is exposed publicly on port 3306", BindAddress: "0.0.0.0:3306"}}
	closed := false
	oldList, oldClosed := exposedDBPortList, dbPortClosed
	exposedDBPortList = func() []watcher.ExposedDBPort { return list }
	dbPortClosed = func(int) bool { return closed }
	defer func() { exposedDBPortList, dbPortClosed = oldList, oldClosed }()

	var got []api.EventRequest
	report := func(e api.EventRequest) { got = append(got, e) }
	last := map[int]string{}

	checkExposedDBPorts(last, report)
	if len(got) != 1 || got[0].Type != "db_exposed" || got[0].Details["bind_address"] != "0.0.0.0:3306" || got[0].Details["port"] != "3306" {
		t.Fatalf("first check: %+v", got)
	}
	checkExposedDBPorts(last, report)
	if len(got) != 1 {
		t.Fatalf("unchanged port reported again: %+v", got)
	}
	list[0].BindAddress = "0.0.0.0:3306, [::]:3306"
	checkExposedDBPorts(last, report)
	if len(got) != 2 || got[1].Details["bind_address"] != "0.0.0.0:3306, [::]:3306" {
		t.Fatalf("new bind: %+v", got)
	}
	closed = true
	checkExposedDBPorts(last, report)
	if len(got) != 2 {
		t.Fatalf("closed by the firewall but reported: %+v", got)
	}
	closed = false
	checkExposedDBPorts(last, report)
	if len(got) != 3 {
		t.Fatalf("reopened: %+v", got)
	}
	// Gone, then back: reported again.
	saved := list
	list = nil
	checkExposedDBPorts(last, report)
	list = saved
	checkExposedDBPorts(last, report)
	if len(got) != 4 {
		t.Fatalf("back after going away: %+v", got)
	}
}
