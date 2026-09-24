package connectors

import "testing"

func TestRevocationCoversOnlyItsScope(t *testing.T) {
	connector := Admission{UserID: "usr_a", Role: RelayRoleConnector, SubjectID: "con_a"}
	phone := Admission{UserID: "usr_a", Role: RelayRoleClient, SubjectID: "dev_a", SessionID: "asn_a"}
	otherPhone := Admission{UserID: "usr_a", Role: RelayRoleClient, SubjectID: "dev_b", SessionID: "asn_b"}
	foreign := Admission{UserID: "usr_b", Role: RelayRoleClient, SubjectID: "dev_a", SessionID: "asn_a"}
	for _, tc := range []struct {
		name       string
		revocation Revocation
		covered    []Admission
		spared     []Admission
	}{
		{"connector", Revocation{UserID: "usr_a", ConnectorID: "con_a"}, []Admission{connector}, []Admission{phone, otherPhone, foreign}},
		{"device", Revocation{UserID: "usr_a", DeviceID: "dev_a"}, []Admission{phone}, []Admission{connector, otherPhone, foreign}},
		{"session", Revocation{UserID: "usr_a", SessionID: "asn_a"}, []Admission{phone}, []Admission{connector, otherPhone, foreign}},
		{"account", Revocation{UserID: "usr_a"}, []Admission{connector, phone, otherPhone}, []Admission{foreign}},
		// A connector and a device can share an identifier only by accident; roles keep them apart.
		{"connector ID never matches a device", Revocation{UserID: "usr_a", ConnectorID: "dev_a"}, nil, []Admission{phone}},
		{"no account covers nothing", Revocation{}, nil, []Admission{connector, phone, foreign}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, admission := range tc.covered {
				if !tc.revocation.Covers(admission) {
					t.Fatalf("%+v should cover %+v", tc.revocation, admission)
				}
			}
			for _, admission := range tc.spared {
				if tc.revocation.Covers(admission) {
					t.Fatalf("%+v must not cover %+v", tc.revocation, admission)
				}
			}
		})
	}
}
