package logsift

import "testing"

func TestIsStackTrace(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want bool
	}{
		{"java stack", "\tat com.example.Service.method(Service.java:42)", true},
		{"python stack", "\tFile \"app.py\", line 10, in main", true},
		{"go goroutine", "goroutine 1 [running]:", true},
		{"traceback", "Traceback (most recent call last):", true},
		{"normal log", "database connection timeout after 3200ms", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isStackTrace(tt.msg); got != tt.want {
				t.Errorf("isStackTrace(%q) = %v, want %v", tt.msg, got, tt.want)
			}
		})
	}
}
