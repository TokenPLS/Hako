package hako

import "testing"

// the row says whether the field was written, as data, so a client can render "not
// set" itself instead of reading the prose the kernel used to put into given. This lock adds
// the fields and keeps the prose; the prose goes once both clients render from these.
func TestRowsSayWhetherTheFieldWasWritten(t *testing.T) {
	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	const document = "tun:\n  mtu: 1500\nrules:\n  - PROCESS-NAME,curl,DIRECT\n  - MATCH,DIRECT\nproxies: []\n"
	rows, err := collectConfigDeviations(document, policy)
	if err != nil {
		t.Fatal(err)
	}
	byField := map[string]configDeviation{}
	for _, row := range rows {
		byField[row.Field] = row
	}

	mtu, ok := byField["tun.mtu"]
	if !ok {
		t.Fatalf("positive control: tun.mtu written 1500 must produce a row: %v", fieldsOf(rows))
	}
	if !mtu.Written || mtu.UpstreamDefault != "" || mtu.Given != "1500" {
		t.Fatalf("a written field is not reported as written with its own value: %+v", mtu)
	}

	dns, ok := byField["dns.enable"]
	if !ok {
		t.Fatalf("positive control: unwritten dns.enable must produce a default row: %v", fieldsOf(rows))
	}
	if dns.Written || dns.UpstreamDefault != "false" {
		t.Fatalf("an unwritten field is not reported as unwritten with the core default: %+v", dns)
	}
	if dns.Given != "not set (core default: false)" {
		t.Fatalf("this lock keeps the prose in given for clients that still render it: %q", dns.Given)
	}

	rules, ok := byField["rules"]
	if !ok {
		t.Fatalf("positive control: the PROCESS-NAME rule must produce a row: %v", fieldsOf(rows))
	}
	if !rules.Written {
		t.Fatalf("a rule the reader wrote is reported as unwritten: %+v", rules)
	}
}
