package connectors

import "testing"

func TestVerifyIdentityProofAcceptsWebCryptoVector(t *testing.T) {
	identity := PublicIdentity{
		Version:   1,
		Suite:     "HPKE-Auth-P256-HKDF-SHA256-AES-256-GCM",
		KeyID:     "EOowPGSZZ7Lj8DI9LOmvylYi5ykIzvQM5FTjEUcOypI",
		PublicKey: "BLNSnFeFgmQ_CxqWsxTJxnbgtIEd-EAGANBhsydPwqp6sGXXCE62K74r3DDMcjwUGWA3pJFwu_xSR3Ce2PsrJPo",
	}
	proof := IdentityProof{
		Challenge: "8dM-8L37KqTpsWp5jzpp27xUqE5iSILAXABZlQeUQ08",
		Signature: "Eq2pNds7wkYH_8a7I1H5NYq-F5eg4_ocUMTwBbDHQkEwvxK13jrrc962JAVWEE58zKW4cxoxDP8K-6MvDL-Org",
	}
	if !verifyIdentityProof(identity, proof) {
		t.Fatal("Go rejected the Web Crypto P-256 proof vector")
	}
	proof.Challenge = "9dM-8L37KqTpsWp5jzpp27xUqE5iSILAXABZlQeUQ08"
	if verifyIdentityProof(identity, proof) {
		t.Fatal("proof verification accepted a changed challenge")
	}
}
