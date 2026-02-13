//go:build linux

package audio

import "github.com/gen2brain/malgo"

var (
	malgoInitContext         = malgo.InitContext
	malgoDefaultDeviceConfig = malgo.DefaultDeviceConfig
	malgoInitDevice          = malgo.InitDevice
	malgoContextUninit       = (*malgo.AllocatedContext).Uninit
	malgoDeviceStart         = (*malgo.Device).Start
	malgoDeviceUninit        = (*malgo.Device).Uninit
)
