package daemon

import "github.com/Bob-Nixkoenner/the_shunt/internal/cgroup"

// torCgroupDir is the absolute directory of a Tor route's group ("" = none).
func torCgroupDir(rel string) string {
	if rel == "" {
		return ""
	}
	m, err := cgroup.Mount()
	if err != nil {
		return ""
	}
	return cgroup.Manager{Mount: m}.Abs(rel)
}
