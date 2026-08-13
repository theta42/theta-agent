package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// cronField is one of the five standard cron fields. It stores the allowed
// values plus whether the field is unrestricted ("*").
type cronField struct {
	values map[int]bool
	isAll  bool
}

func (f cronField) contains(v int) bool {
	if f.isAll {
		return true
	}
	return f.values[v]
}

func newCronField() cronField {
	return cronField{values: map[int]bool{}}
}

// monthNames / dowNames map the named forms (JAN, SUN, ...) to their numbers.
var monthNames = map[string]int{
	"JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
	"JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12,
}
var dowNames = map[string]int{
	"SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6,
}

// parseCronRange parses one comma-separated element of a field (e.g. "*/5",
// "1-5", "7", "JAN", "SUN"). names maps named tokens, min/max bound the field.
func parseCronRange(tok string, names map[string]int, min, max int) ([]int, error) {
	orig := tok
	// Named token (may be a single value only).
	if v, ok := names[tok]; ok {
		return []int{v}, nil
	}
	tok = strings.ToUpper(tok)
	if v, ok := names[tok]; ok {
		return []int{v}, nil
	}

	base := ""
	step := 1
	if i := strings.IndexByte(tok, '/'); i >= 0 {
		base = tok[:i]
		s := tok[i+1:]
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("bad step in %q", orig)
		}
		step = n
	} else {
		base = tok
	}

	lo, hi := min, max
	hadRange := false
	if base == "*" {
		// whole field
	} else if strings.Contains(base, "-") {
		parts := strings.SplitN(base, "-", 2)
		a, aerr := strconv.Atoi(parts[0])
		b, berr := strconv.Atoi(parts[1])
		if aerr != nil || berr != nil {
			return nil, fmt.Errorf("bad range in %q", orig)
		}
		lo, hi = a, b
		hadRange = true
	} else {
		v, err := strconv.Atoi(base)
		if err != nil {
			return nil, fmt.Errorf("bad value %q", orig)
		}
		lo, hi = v, v
		hadRange = true
	}

	var out []int
	if hadRange && step > 1 {
		for v := lo; v <= hi; v += step {
			out = append(out, v)
		}
	} else if hadRange {
		for v := lo; v <= hi; v++ {
			out = append(out, v)
		}
	} else {
		// "*" or "*/n"
		for v := min; v <= max; v += step {
			out = append(out, v)
		}
	}
	return out, nil
}

// parseCronField parses a full field (comma-separated elements).
func parseCronField(field string, names map[string]int, min, max int) (cronField, error) {
	f := newCronField()
	if field == "*" {
		f.isAll = true
		return f, nil
	}
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		vals, err := parseCronRange(part, names, min, max)
		if err != nil {
			return f, err
		}
		for _, v := range vals {
			f.values[v] = true
		}
	}
	if len(f.values) == 0 {
		return f, fmt.Errorf("empty cron field %q", field)
	}
	return f, nil
}

// cronSchedule is a parsed 5-field cron expression.
type cronSchedule struct {
	minute cronField
	hour   cronField
	dom    cronField
	month  cronField
	dow    cronField
}

// parseCronSchedule parses the standard five-field cron expression.
func parseCronSchedule(expr string) (*cronSchedule, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron expression needs 5 fields, got %d: %q", len(fields), expr)
	}
	s := &cronSchedule{}
	var err error
	if s.minute, err = parseCronField(fields[0], nil, 0, 59); err != nil {
		return nil, err
	}
	if s.hour, err = parseCronField(fields[1], nil, 0, 23); err != nil {
		return nil, err
	}
	if s.dom, err = parseCronField(fields[2], nil, 1, 31); err != nil {
		return nil, err
	}
	if s.month, err = parseCronField(fields[3], monthNames, 1, 12); err != nil {
		return nil, err
	}
	if s.dow, err = parseCronField(fields[4], dowNames, 0, 6); err != nil {
		return nil, err
	}
	return s, nil
}

// dayMatches implements cron's day-of-month / day-of-week rule: when both are
// restricted, a match on either satisfies the day; when only one is restricted
// it must match.
func (s *cronSchedule) dayMatches(t time.Time) bool {
	domRestricted := !s.dom.isAll
	dowRestricted := !s.dow.isAll
	domMatch := s.dom.contains(t.Day())
	dowMatch := s.dow.contains(int(t.Weekday()))
	if domRestricted && dowRestricted {
		return domMatch || dowMatch
	}
	if domRestricted {
		return domMatch
	}
	if dowRestricted {
		return dowMatch
	}
	return true
}

// matches reports whether the schedule fires at t (local time).
func (s *cronSchedule) matches(t time.Time) bool {
	return s.minute.contains(t.Minute()) &&
		s.hour.contains(t.Hour()) &&
		s.month.contains(int(t.Month())) &&
		s.dayMatches(t)
}

const cronSearchCap = 366 * 24 * 60 // ~1 year of minutes

// next returns the first fire time strictly after `after`, or the zero time if
// none within the search window.
func (s *cronSchedule) next(after time.Time) time.Time {
	t := after.In(time.Local).Truncate(time.Minute).Add(time.Minute)
	for i := 0; i < cronSearchCap; i++ {
		if s.matches(t) {
			return t
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}
}

// prev returns the last fire time strictly before `before`, or the zero time.
func (s *cronSchedule) prev(before time.Time) time.Time {
	t := before.In(time.Local).Truncate(time.Minute).Add(-time.Minute)
	for i := 0; i < cronSearchCap; i++ {
		if s.matches(t) {
			return t
		}
		t = t.Add(-time.Minute)
	}
	return time.Time{}
}
