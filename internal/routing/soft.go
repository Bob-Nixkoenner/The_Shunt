package routing

import "errors"

// SoftError is a route Sync could not copy into a link or LAN table (an
// interface coming up, a gateway not reachable yet). The kill switch route
// of that table is in place, so its traffic is blocked meanwhile: worth a
// warning and a retry, not a failed reload.
type SoftError struct{ Err error }

func (e *SoftError) Error() string { return e.Err.Error() }
func (e *SoftError) Unwrap() error { return e.Err }

// Split separates the soft errors in err (as returned by Sync) from the
// rest.
func Split(err error) (hard error, soft []error) {
	var hards []error
	var walk func(error)
	walk = func(e error) {
		if e == nil {
			return
		}
		if j, ok := e.(interface{ Unwrap() []error }); ok {
			for _, x := range j.Unwrap() {
				walk(x)
			}
			return
		}
		var s *SoftError
		if errors.As(e, &s) {
			soft = append(soft, e)
			return
		}
		hards = append(hards, e)
	}
	walk(err)
	return errors.Join(hards...), soft
}
