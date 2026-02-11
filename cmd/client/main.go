package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	tea "github.com/charmbracelet/bubbletea"
)

type programRunner interface {
	Run() (tea.Model, error)
}

type programFactory func(tea.Model, ...tea.ProgramOption) programRunner

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, newProgram programFactory) error {
	fs := flag.NewFlagSet("dialtone", flag.ContinueOnError)
	fs.SetOutput(stderr)
	serverAddr := fs.String("server", "", "dialtone server address")
	voiceIPCAddr := fs.String("voice-ipc", defaultVoiceIPCAddr(), "voice daemon ipc socket/pipe")
	voiceAuto := fs.Bool("voice-auto", true, "auto-start voice daemon when needed")
	voicedPath := fs.String("voiced", "", "path to voiced binary")
	voiceDebug := fs.Bool("voice-debug", false, "write voiced logs to a file")
	voiceLogPath := fs.String("voice-log", "", "path to voiced log file")
	voicePTT := fs.String("voice-ptt", "", "override voiced PTT binding (empty to disable)")
	voiceVAD := fs.Int("voice-vad", 0, "override voiced VAD threshold (lower = more sensitive)")
	voiceMeter := fs.Bool("voice-meter", false, "enable voiced mic level logging")
	voiceSTUN := fs.String("voice-stun", "", "comma-separated STUN servers for voiced")
	voiceTURN := fs.String("voice-turn", "", "comma-separated TURN servers for voiced")
	voiceTURNUser := fs.String("voice-turn-user", "", "TURN username for voiced")
	voiceTURNPass := fs.String("voice-turn-pass", "", "TURN password for voiced")
	if err := fs.Parse(args); err != nil {
		return err
	}

	serverSet := false
	voicePTTSet := false
	voiceVADSet := false
	voiceMeterSet := false
	voiceSTUNSet := false
	voiceTURNSet := false
	voiceTURNUserSet := false
	voiceTURNPassSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "server" {
			serverSet = true
		}
		switch f.Name {
		case "voice-ptt":
			voicePTTSet = true
		case "voice-vad":
			voiceVADSet = true
		case "voice-meter":
			voiceMeterSet = true
		case "voice-stun":
			voiceSTUNSet = true
		case "voice-turn":
			voiceTURNSet = true
		case "voice-turn-user":
			voiceTURNUserSet = true
		case "voice-turn-pass":
			voiceTURNPassSet = true
		}
	})
	if !serverSet {
		*serverAddr = ""
	}
	if voiceVADSet && *voiceVAD <= 0 {
		return fmt.Errorf("voice-vad must be > 0")
	}

	voiceArgs := make([]string, 0, 12)
	if voicePTTSet {
		voiceArgs = append(voiceArgs, "-ptt", *voicePTT)
	}
	if voiceVADSet {
		voiceArgs = append(voiceArgs, "-vad-threshold", strconv.Itoa(*voiceVAD))
	}
	if voiceMeterSet && *voiceMeter {
		voiceArgs = append(voiceArgs, "-meter")
	}
	if voiceSTUNSet {
		voiceArgs = append(voiceArgs, "-stun", *voiceSTUN)
	}
	if voiceTURNSet {
		voiceArgs = append(voiceArgs, "-turn", *voiceTURN)
	}
	if voiceTURNUserSet {
		voiceArgs = append(voiceArgs, "-turn-user", *voiceTURNUser)
	}
	if voiceTURNPassSet {
		voiceArgs = append(voiceArgs, "-turn-pass", *voiceTURNPass)
	}

	api := NewAPIClient(*serverAddr)
	m := newRootModel(api, *voiceIPCAddr)
	m.voiceAutoStart = *voiceAuto
	m.voicedPath = *voicedPath
	m.voiceArgs = voiceArgs
	m.voiceDebug = *voiceDebug
	m.voiceLogPath = *voiceLogPath

	if newProgram == nil {
		newProgram = func(model tea.Model, options ...tea.ProgramOption) programRunner {
			return tea.NewProgram(model, options...)
		}
	}

	p := newProgram(m, tea.WithAltScreen(), tea.WithInput(stdin), tea.WithOutput(stdout))
	_, err := p.Run()
	return err
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
