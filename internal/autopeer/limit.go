package autopeer

import (
	"sync"
	"time"
)

// Limiter counts PRs per login and in total over a sliding hour. It is in
// memory: a restart forgets it, which is fine for a single replica.
type Limiter struct {
	PerKey, Total int
	Window        time.Duration
	Now           func() time.Time

	mu    sync.Mutex
	byKey map[string][]time.Time
	all   []time.Time
}

func prune(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	return ts[i:]
}

// Allow records one event for key if both limits allow it.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.Now != nil {
		now = l.Now()
	}
	w := l.Window
	if w == 0 {
		w = time.Hour
	}
	cutoff := now.Add(-w)
	if l.byKey == nil {
		l.byKey = map[string][]time.Time{}
	}
	l.all = prune(l.all, cutoff)
	k := prune(l.byKey[key], cutoff)
	if len(k) >= l.PerKey || len(l.all) >= l.Total {
		l.byKey[key] = k
		return false
	}
	l.byKey[key] = append(k, now)
	l.all = append(l.all, now)
	return true
}
