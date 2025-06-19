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
