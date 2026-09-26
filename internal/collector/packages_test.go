package collector

import "testing"

func TestParseDpkgKeepsInstalledWithSource(t *testing.T) {
	out := "ii \topenssh-server\t1:9.2p1-2+deb12u3\topenssh\t1:9.2p1-2+deb12u3\n" +
		"rc \told-thing\t1.0\told-thing\t1.0\n" +
		"ii \tlibssl3\t3.0.15-1~deb12u1\topenssl\t3.0.15-1~deb12u1\n" +
		"ii \tbash\t5.2.15-2+b7\t\t\n"
	got := parseDpkg(out)
	if len(got) != 3 {
		t.Fatalf("got %d packages: %+v", len(got), got)
	}
	if got[0].Source != "openssh" || got[1].Source != "openssl" {
		t.Fatalf("sources: %+v", got)
	}
	if got[2].Source != "bash" || got[2].SourceVersion != "5.2.15-2+b7" {
		t.Fatalf("missing source falls back to the binary: %+v", got[2])
	}
}

func TestParseRPM(t *testing.T) {
	out := "openssl-libs\t1:3.0.7-27.el9\topenssl-3.0.7-27.el9.src.rpm\n" +
		"gpg-pubkey\t3228467c-613798eb\t(none)\n" +
		"bash\t5.1.8-9.el9\tbash-5.1.8-9.el9.src.rpm\n"
	got := parseRPM(out)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Name != "openssl-libs" || got[0].Version != "1:3.0.7-27.el9" || got[0].Source != "openssl" {
		t.Fatalf("got %+v", got[0])
	}
}
