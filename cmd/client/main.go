package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	serverAddr := flag.String("server", "", "dialtone server address")
	flag.Parse()

	serverSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "server" {
			serverSet = true
		}
	})
	if !serverSet {
		*serverAddr = ""
	}

	api := NewAPIClient(*serverAddr)
	m := newRootModel(api)

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
