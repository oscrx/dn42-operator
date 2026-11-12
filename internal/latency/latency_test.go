package latency

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func ms(f float64) time.Duration { return time.Duration(f * float64(time.Millisecond)) }

func TestCommunity(t *testing.T) {
	cases := []struct {
		rtt  time.Duration
		want int32
	}{
		{0, 1}, {ms(0.5), 1}, {ms(2.7), 1}, {ms(2.71), 2}, {ms(7.3), 2}, {ms(7.31), 3},
		{ms(20), 3}, {ms(20.1), 4}, {ms(55), 4}, {ms(56), 5}, {ms(148), 5}, {ms(149), 6},
		{ms(403), 6}, {ms(404), 7}, {ms(1097), 7}, {ms(1098), 8}, {ms(2981), 8}, {ms(2982), 9},
		{time.Minute, 9},
	}
	for _, c := range cases {
		if got := Community(c.rtt); got != c.want {
			t.Errorf("Community(%v) = %d, want %d", c.rtt, got, c.want)
		}
	}
}

func TestMedian(t *testing.T) {
	m, err := Median([]time.Duration{ms(9), ms(1), ms(5)}, 3)
	if err != nil || m != ms(5) {
		t.Errorf("odd: %v %v", m, err)
	}
	m, err = Median([]time.Duration{ms(4), ms(1), ms(2), ms(100)}, 4)
	if err != nil || m != ms(3) {
		t.Errorf("even: %v %v", m, err)
	}
	// 5 of 10 answered is enough, 4 is not.
	if _, err := Median(make([]time.Duration, 5), 10); err != nil {
		t.Error(err)
	}
	if _, err := Median(make([]time.Duration, 4), 10); err == nil {
		t.Error("4 of 10 accepted")
	}
	if _, err := Median(nil, 10); err == nil {
		t.Error("no samples accepted")
	}
}

type fakePinger struct {
	rtts []time.Duration
	err  error
}

func (f fakePinger) Ping(context.Context, netip.Addr, int, time.Duration) ([]time.Duration, error) {
	return f.rtts, f.err
}

func TestMeasure(t *testing.T) {
	a := netip.MustParseAddr("2001:db8::1")
	rtt, lat, err := Measure(context.Background(), fakePinger{rtts: []time.Duration{ms(10), ms(30), ms(12), ms(11), ms(500)}}, a, 10, 0)
	if err != nil || rtt != ms(12) || lat != 3 {
		t.Errorf("%v %d %v", rtt, lat, err)
	}
	if _, _, err := Measure(context.Background(), fakePinger{err: errors.New("unreachable")}, a, 10, 0); err == nil {
		t.Error("error swallowed")
	}
}
