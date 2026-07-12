package common

import "testing"

func TestAuthSchemeValid(t *testing.T) {
	if len(AllAuthSchemes) != 9 {
		t.Errorf("AllAuthSchemes: got %d, want 9", len(AllAuthSchemes))
	}
	for _, s := range AllAuthSchemes {
		if !s.Valid() {
			t.Errorf("auth scheme %q should be valid", s)
		}
	}
	if AuthScheme("totp").Valid() {
		t.Error("unknown auth scheme should be invalid")
	}
	// AuthUnknown is a defined scheme (not-determined), distinct from AuthNone.
	if AuthUnknown == AuthNone {
		t.Error("AuthUnknown must be distinct from AuthNone")
	}
}

func TestAssessmentStateValid(t *testing.T) {
	if len(AllAssessmentStates) != 3 {
		t.Errorf("AllAssessmentStates: got %d, want 3", len(AllAssessmentStates))
	}
	for _, s := range AllAssessmentStates {
		if !s.Valid() {
			t.Errorf("assessment state %q should be valid", s)
		}
	}
	if AssessmentState("maybe").Valid() {
		t.Error("unknown assessment state should be invalid")
	}
	if AssessmentNotAssessed == AssessmentUnknown {
		t.Error("not_assessed must be distinct from unknown")
	}
}
