package policyevaluation

import (
	"reflect"
	"testing"
)

func TestRiskLevel_String(t *testing.T) {
	tests := []struct {
		name string
		rl   RiskLevel
		want string
	}{
		{"Low", RiskLevelLow, "Low"},
		{"Medium", RiskLevelMedium, "Medium"},
		{"High", RiskLevelHigh, "High"},
		{"Critical", RiskLevelCritical, "Critical"},
		{"Unknown", RiskLevel(99), ""}, // Test undefined value
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rl.String(); got != tt.want {
				t.Errorf("RiskLevel.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRiskTag_String(t *testing.T) {
	tests := []struct {
		name string
		rt   RiskTag
		want string
	}{
		{"Spoofing", Spoofing, "Spoofing"},
		{"DataExposure", DataExposure, "DataExposure"},
		{"EmptyTag", RiskTag(""), ""},
		{"CustomTag", RiskTag("MyCustomTag"), "MyCustomTag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rt.String(); got != tt.want {
				t.Errorf("RiskTag.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRiskTags_String(t *testing.T) {
	tests := []struct {
		name string
		rs   RiskTags
		want string
	}{
		{"Multiple tags", RiskTags{Spoofing, Tampering, DataExposure}, "Spoofing,Tampering,DataExposure"},
		{"Single tag", RiskTags{PrivilegeEscalation}, "PrivilegeEscalation"},
		{"No tags", RiskTags{}, ""},
		{"Empty tag string", RiskTags{RiskTag("")}, ""},
		{"Mixed tags", RiskTags{PodExec, RiskTag("Custom"), DenialOfService}, "PodExec,Custom,DenialOfService"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rs.String(); got != tt.want {
				t.Errorf("RiskTags.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRiskTags_Strings(t *testing.T) {
	tests := []struct {
		name string
		rs   RiskTags
		want []string
	}{
		{"Multiple tags", RiskTags{Spoofing, Tampering}, []string{"Spoofing", "Tampering"}},
		{"Single tag", RiskTags{DataLoss}, []string{"DataLoss"}},
		{"No tags", RiskTags{}, []string{}},
		{"Empty tag string", RiskTags{RiskTag("")}, []string{""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rs.Strings(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RiskTags.Strings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRiskTags_StringSlice(t *testing.T) {
	tests := []struct {
		name  string
		rs    RiskTags
		limit int
		want  []string
	}{
		{"Limit less than length", RiskTags{Spoofing, Tampering, Repudiation}, 2, []string{"Spoofing", "Tampering", "(1 more)"}},
		{"Limit equal to length", RiskTags{Spoofing, Tampering}, 2, []string{"Spoofing", "Tampering"}},
		{"Limit greater than length", RiskTags{Spoofing, Tampering}, 5, []string{"Spoofing", "Tampering"}},
		{"Limit zero", RiskTags{Spoofing, Tampering}, 0, []string{"(2 more)"}},
		{"Limit one", RiskTags{Spoofing, Tampering, Repudiation}, 1, []string{"Spoofing", "(2 more)"}},
		{"Empty tags, limit > 0", RiskTags{}, 2, []string{}},
		{"Empty tags, limit 0", RiskTags{}, 0, []string{}}, // Corrected expectation: should be empty or handled as "0 more" if that's desired
		{"Tags with one element, limit 0", RiskTags{Spoofing}, 0, []string{"(1 more)"}},
		{"Tags with one element, limit 1", RiskTags{Spoofing}, 1, []string{"Spoofing"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Special case for empty tags, limit 0, as it results in empty slice not "0 more"
			if len(tt.rs) == 0 && tt.limit == 0 {
				if got := tt.rs.StringSlice(tt.limit); len(got) != 0 {
					t.Errorf("RiskTags.StringSlice() for empty tags, limit 0 = %v, want []", got)
				}
				return // skip further checks for this specific case
			}

			if got := tt.rs.StringSlice(tt.limit); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RiskTags.StringSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Placeholder for testing Policy.String() if it were to exist.
// func TestPolicy_String(t *testing.T) { ... }

// Based on the current types.go, Risk, Control, and EvaluationResult
// do not have explicit String() methods. If they are simple structs,
// their default fmt.Sprintf("%v", ...) might be sufficient, or they
// might not require string representations for the tool's purposes.
// If String() methods are added later, tests should be created here.
