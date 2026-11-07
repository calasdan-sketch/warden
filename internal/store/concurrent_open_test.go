package store

import (
	"path/filepath"
	"sync"
	"testing"
)

// A fleet runs many short-lived `warden hook` processes against one database
// file. Opening it concurrently must wait, never fail with "database is
// locked" (the hook would then deny a perfectly allowed call, fail-closed).
func TestConcurrentOpenNeverFailsLocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warden.db")
	for round := 0; round < 5; round++ {
		var wg sync.WaitGroup
		errs := make(chan error, 24)
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s, err := Open(path)
				if err != nil {
					errs <- err
					return
				}
				s.Close()
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("round %d: open failed under concurrency: %v", round, err)
		}
	}
}
