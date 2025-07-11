package policyevaluation

import (
	_ "embed"
	"reflect"
	"sort"
	"testing"
)

func TestUniqueRiskTags(t *testing.T) {
	type args struct {
		tags []RiskTag
	}
	tests := []struct {
		name string
		args args
		want []RiskTag
	}{
		{
			name: "empty list",
			args: args{
				tags: []RiskTag{},
			},
			want: []RiskTag{},
		},
		{
			name: "duplicate tags",
			args: args{
				tags: []RiskTag{Spoofing, Spoofing, Tampering},
			},
			want: []RiskTag{Spoofing, Tampering},
		},
		{
			name: "single tag",
			args: args{
				tags: []RiskTag{Spoofing},
			},
			want: []RiskTag{Spoofing},
		},
		{
			name: "multiple tags",
			args: args{
				tags: []RiskTag{Spoofing, Tampering, DataExposure},
			},
			want: []RiskTag{Spoofing, Tampering, DataExposure},
		},
		{
			name: "empty tag string",
			args: args{
				tags: []RiskTag{RiskTag("")},
			},
			want: []RiskTag{""},
		},
		{
			name: "mixed tags",
			args: args{
				tags: []RiskTag{Spoofing, RiskTag("Custom"), DenialOfService},
			},
			want: []RiskTag{Spoofing, RiskTag("Custom"), DenialOfService},
		},
		{
			name: "empty tag string and duplicate",
			args: args{
				tags: []RiskTag{RiskTag(""), RiskTag(""), Spoofing, Spoofing},
			},
			want: []RiskTag{"", Spoofing},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UniqueRiskTags(tt.args.tags)
			// Sort both slices before comparison to make the test order-agnostic
			sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
			sort.Slice(tt.want, func(i, j int) bool { return tt.want[i] < tt.want[j] })

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UniqueRiskTags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateRiskRule(t *testing.T) {
	base := RiskRule{ID: 1, Name: "test", RoleType: "Role", RiskLevel: RiskLevelLow}
	cases := []struct {
		name    string
		rule    RiskRule
		wantErr bool
	}{
		{"valid", base, false},
		{"missing id", RiskRule{Name: "n", RoleType: "Role", RiskLevel: RiskLevelLow}, true},
		{"missing name", RiskRule{ID: 2, RoleType: "Role", RiskLevel: RiskLevelLow}, true},
		{"bad role", RiskRule{ID: 3, Name: "n", RoleType: "Bad", RiskLevel: RiskLevelLow}, true},
		{"bad level", RiskRule{ID: 4, Name: "n", RoleType: "Role", RiskLevel: 99}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateRiskRule(c.rule)
			if (err != nil) != c.wantErr {
				t.Fatalf("validateRiskRule() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestLoadRiskRules(t *testing.T) {
	orig := risksYAMLBytes
	defer func() { risksYAMLBytes = orig }()

	t.Run("invalid yaml", func(t *testing.T) {
		risksYAMLBytes = []byte("bad:")
		if err := loadRiskRules(); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("invalid rule", func(t *testing.T) {
		risksYAMLBytes = []byte("- id: 0\n  name: a\n  role_type: Role\n  risk_level: 0")
		if err := loadRiskRules(); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("valid", func(t *testing.T) {
		risksYAMLBytes = []byte("- id: 1\n  name: a\n  role_type: Role\n  risk_level: RiskLevelLow")
		if err := loadRiskRules(); err != nil {
			t.Fatalf("loadRiskRules() error = %v", err)
		}
		r := GetRiskRules()
		if len(r) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(r))
		}
		r[0].Name = "changed"
		if riskRules[0].Name == "changed" {
			t.Error("GetRiskRules() returned reference")
		}
	})
}
