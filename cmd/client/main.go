package main

import (
	"flag"
	"fmt"
	"io"
	"os"

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
	if err := fs.Parse(args); err != nil {
		return err
	}

	serverSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "server" {
			serverSet = true
		}
	})
	if !serverSet {
		*serverAddr = ""
	}

	api := NewAPIClient(*serverAddr)
	m := newRootModel(api)

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
