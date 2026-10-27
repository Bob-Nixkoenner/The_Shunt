//go:build !linux

package daemon

func torCgroupDir(string) string { return "" }
