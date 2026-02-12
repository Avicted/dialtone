//go:build !linux

package main

import "fmt"

func newPortalPTTBackend(string) (pttBackend, error) {
	return nil, fmt.Errorf("xdg desktop portal global shortcuts are only available on linux")
}
