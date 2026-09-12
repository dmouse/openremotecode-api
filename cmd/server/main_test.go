package main

import "testing"

func TestValidProductionVerificationURI(t *testing.T) {
	for _, test := range []struct {
		value string
		valid bool
	}{
		{value: "https://remote.example.test/pair", valid: true},
		{value: "http://remote.example.test/pair", valid: false},
		{value: "https://user:password@remote.example.test/pair", valid: false},
		{value: "https://remote.example.test/pair?code=secret", valid: false},
		{value: "https:///pair", valid: false},
		{value: "", valid: false},
	} {
		if actual := validProductionVerificationURI(test.value); actual != test.valid {
			t.Errorf("validProductionVerificationURI(%q) = %t, want %t", test.value, actual, test.valid)
		}
	}
}
