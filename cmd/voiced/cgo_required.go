//go:build !cgo

package main

// This file forces a build failure when CGO is disabled.
// The voice daemon requires CGO for audio capture and Opus encoding.
//
// #include <stdlib.h>
import "C"
