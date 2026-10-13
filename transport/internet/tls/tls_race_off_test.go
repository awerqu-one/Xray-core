//go:build !race

package tls

// recRaceDetector is false in a normal build. See tls_race_on_test.go.
const recRaceDetector = false
