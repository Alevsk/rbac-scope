package policyevaluation

import (
	_ "embed"
	"reflect"
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
			if got := UniqueRiskTags(tt.args.tags); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UniqueRiskTags() = %v, want %v", got, tt.want)
			}
		})
	}
}
