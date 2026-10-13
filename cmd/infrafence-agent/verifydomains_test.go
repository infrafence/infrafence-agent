package main

import (
	"fmt"
	"reflect"
	"testing"
)

func TestChooseVerifyDomains(t *testing.T) {
	got := chooseVerifyDomains(
		[]string{"quiet.example", "Shop.Example", "*.wild.example", "_", "shop.example", "blog.example."},
		[]string{"shop.example", "scanner-host.example", "blog.example"},
	)
	want := []string{"blog.example", "shop.example", "quiet.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	var many, logged []string
	for i := 0; i < 30; i++ {
		many = append(many, fmt.Sprintf("s%02d.example", i))
	}
	logged = []string{"s29.example"}
	got = chooseVerifyDomains(many, logged)
	if len(got) != maxVerifyDomains || got[0] != "s29.example" {
		t.Fatalf("got %d domains starting with %q, want %d starting with the logged one", len(got), got[0], maxVerifyDomains)
	}
}
