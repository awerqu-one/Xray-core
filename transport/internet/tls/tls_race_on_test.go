//go:build race

package tls

// recRaceDetector is true when the race detector is built in. The allocation test is skipped then,
// because race instrumentation changes the allocation counts from run to run.
const recRaceDetector = true
