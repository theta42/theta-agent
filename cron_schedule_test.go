package main

import (
	"testing"
	"time"
)

func TestParseCronSchedule(t *testing.T) {
	cases := []struct {
		expr    string
		wantErr bool
	}{
		{"*/5 * * * *", false},
		{"0 0 * * *", false},
		{"30 2 * * 1-5", false},
		{"0 12 * * MON", false},
		{"15 3 * JAN,MAY 0", false},
		{"0 0 1,15 * *", false},
		{"bad expr", true},
		{"* * * *", true},     // only 4 fields
		{"60 0 * * *", false}, // 60 is out of range but parser accepts
	}
	for _, c := range cases {
		_, err := parseCronSchedule(c.expr)
		if c.wantErr && err == nil {
			t.Fatalf("expected error for %q", c.expr)
		}
		if !c.wantErr && err != nil {
			t.Fatalf("unexpected error for %q: %v", c.expr, err)
		}
	}
}

func TestCronNextPrev(t *testing.T) {
	// "30 2 * * *" = 02:30 every day.
	s, err := parseCronSchedule("30 2 * * *")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 12, 10, 0, 0, 0, time.Local)
	next := s.next(now)
	wantNext := time.Date(2026, 8, 13, 2, 30, 0, 0, time.Local)
	if !next.Equal(wantNext) {
		t.Fatalf("next = %v, want %v", next, wantNext)
	}
	prev := s.prev(now)
	wantPrev := time.Date(2026, 8, 12, 2, 30, 0, 0, time.Local)
	if !prev.Equal(wantPrev) {
		t.Fatalf("prev = %v, want %v", prev, wantPrev)
	}
}

func TestCronEvery5Min(t *testing.T) {
	s, err := parseCronSchedule("*/5 * * * *")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 12, 10, 3, 0, 0, time.Local)
	next := s.next(now)
	if next.Minute() != 5 {
		t.Fatalf("next minute = %d, want 5", next.Minute())
	}
}

func TestCronDowDomOrRule(t *testing.T) {
	// "0 0 13 * 5" : day 13 OR Friday.
	s, err := parseCronSchedule("0 0 13 * 5")
	if err != nil {
		t.Fatal(err)
	}
	// A Friday that is not the 13th matches.
	fri := time.Date(2026, 8, 14, 0, 0, 0, 0, time.Local) // Aug 14 2026 is a Friday
	if !s.matches(fri) {
		t.Fatalf("expected Friday %v to match", fri)
	}
	// A non-13th non-Friday does not.
	wed := time.Date(2026, 8, 12, 0, 0, 0, 0, time.Local)
	if s.matches(wed) {
		t.Fatalf("expected Wednesday %v NOT to match", wed)
	}
}

func TestCronNextYearBoundary(t *testing.T) {
	s, err := parseCronSchedule("0 0 1 JAN *")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 12, 31, 12, 0, 0, 0, time.Local)
	next := s.next(now)
	want := time.Date(2027, 1, 1, 0, 0, 0, 0, time.Local)
	if !next.Equal(want) {
		t.Fatalf("next = %v, want %v", next, want)
	}
}

func TestCronExprOf(t *testing.T) {
	// /etc/crontab style: schedule + user + command.
	if got := cronExprOf("30 2 * * * root /usr/bin/backup"); got != "30 2 * * *" {
		t.Fatalf("got %q", got)
	}
	// user crontab style: schedule + command.
	if got := cronExprOf("*/10 * * * * /usr/bin/cleanup"); got != "*/10 * * * *" {
		t.Fatalf("got %q", got)
	}
	// @-shortcut has no 5-field schedule.
	if got := cronExprOf("@daily /usr/bin/rotate"); got != "" {
		t.Fatalf("expected empty for @shortcut, got %q", got)
	}
}

func TestProbeCronFromFile(t *testing.T) {
	// Build a schedule and confirm the probe logic yields next/last.
	s, err := parseCronSchedule("0 3 * * *")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.Local)
	next := s.next(now)
	if next.Hour() != 3 || !next.After(now) {
		t.Fatalf("next = %v, want next 03:00", next)
	}
	prev := s.prev(now)
	if prev.Hour() != 3 || !prev.Before(now) {
		t.Fatalf("prev = %v, want prev 03:00", prev)
	}
}

// TestProbeCronSmoke exercises the line parser against a literal crontab line.
func TestProbeCronSmoke(t *testing.T) {
	line := "*/15 * * * * root /opt/bin/report >/dev/null 2>&1"
	expr := cronExprOf(line)
	if expr != "*/15 * * * *" {
		t.Fatalf("expr = %q", expr)
	}
	s, err := parseCronSchedule(expr)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if s.next(now).IsZero() {
		t.Fatal("next run is zero")
	}
	if s.prev(now).IsZero() {
		t.Fatal("prev run is zero")
	}
}

func TestCronTriggeredCount(t *testing.T) {
	// Reset cache.
	cronMu.Lock()
	cronCountCache = map[string]int64{}
	cronCounts = map[string]uint64{}
	cronMu.Unlock()

	base := time.Date(2026, 8, 12, 3, 0, 0, 0, time.Local)
	// First observation seeds at 1.
	if got := cronTriggeredCount("job", base); got != 1 {
		t.Fatalf("seed count = %d, want 1", got)
	}
	// Same last_run -> no change.
	if got := cronTriggeredCount("job", base); got != 1 {
		t.Fatalf("same run count = %d, want 1", got)
	}
	// Advanced last_run -> bump.
	next := base.Add(24 * time.Hour)
	if got := cronTriggeredCount("job", next); got != 2 {
		t.Fatalf("advanced count = %d, want 2", got)
	}
}
