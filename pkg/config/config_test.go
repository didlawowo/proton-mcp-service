package config

import "testing"

func TestLoadAllowWritesWithoutKey(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"unset keeps the gate closed", "", false},
		{"true opens the gate", "true", true},
		{"false keeps the gate closed", "false", false},
		{"invalid value keeps the gate closed", "yes", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PROTON_ALLOW_WRITES_WITHOUT_KEY", tt.value)
			if got := Load().AllowWritesWithoutKey; got != tt.want {
				t.Errorf("AllowWritesWithoutKey = %v, want %v", got, tt.want)
			}
		})
	}
}
