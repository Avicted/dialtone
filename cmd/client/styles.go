package main

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	appNameStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("212"))

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252")).
			Bold(true)

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("243"))

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true)

	sentMsgStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("114"))

	recvMsgStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("69"))

	historyMsgStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("242"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	separatorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("238"))

	activeInputStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("212")).
				Bold(true)

	connectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("114"))

	disconnectedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("196"))

	sidebarTitleStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("246")).
				Bold(true)

	sidebarOnlineStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("114"))

	sidebarOfflineStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("240"))

	sidebarBoxStyle = lipgloss.NewStyle().
			BorderLeft(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("238")).
			PaddingLeft(1)
)

func centerText(text string, width int) string {
	if width <= 0 {
		return text
	}
	textWidth := lipgloss.Width(text)
	if textWidth >= width {
		return text
	}
	pad := (width - textWidth) / 2
	return strings.Repeat(" ", pad) + text
}

func separator(width int) string {
	w := width - 4
	if w < 1 {
		w = 1
	}
	return separatorStyle.Render("  " + strings.Repeat("─", w))
}
