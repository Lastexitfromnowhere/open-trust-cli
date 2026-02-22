// ui.go centralises all terminal output helpers: colours, spinner, progress bar.
// Every other file in cmd/ should use these functions instead of raw fmt.Printf
// to ensure consistent styling and easy --no-colour support.
package cmd

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ── Colour toggle ─────────────────────────────────────────────────────────────

// colour is set at the start of each command via SetColour().
// Default is true (assume a TTY).
var colour = true

// SetColour enables or disables ANSI output for the current command.
func SetColour(on bool) { colour = on }

// ── ANSI escape codes ─────────────────────────────────────────────────────────

const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
)

// ── String decorators (return a formatted string, do not print) ───────────────

func colOK(s string) string {
	if colour {
		return ansiGreen + "[✓]" + ansiReset + " " + s
	}
	return "[OK]  " + s
}

func colFail(s string) string {
	if colour {
		return ansiRed + "[✗]" + ansiReset + " " + s
	}
	return "[FAIL] " + s
}

func colWarn(s string) string {
	if colour {
		return ansiYellow + "[!]" + ansiReset + " " + s
	}
	return "[WARN] " + s
}

func colInfo(s string) string {
	if colour {
		return ansiCyan + "[i]" + ansiReset + " " + s
	}
	return "[INFO] " + s
}

func colBold(s string) string {
	if colour {
		return ansiBold + s + ansiReset
	}
	return s
}

func colDim(s string) string {
	if colour {
		return ansiDim + s + ansiReset
	}
	return s
}

// ── Direct printers ───────────────────────────────────────────────────────────

func printOK(format string, a ...interface{}) {
	fmt.Printf("  "+colOK(fmt.Sprintf(format, a...))+"\n")
}

func printFail(format string, a ...interface{}) {
	fmt.Printf("  "+colFail(fmt.Sprintf(format, a...))+"\n")
}

func printWarn(format string, a ...interface{}) {
	fmt.Printf("  "+colWarn(fmt.Sprintf(format, a...))+"\n")
}

func printInfo(format string, a ...interface{}) {
	fmt.Printf("  "+colInfo(fmt.Sprintf(format, a...))+"\n")
}

// ── Section headers ───────────────────────────────────────────────────────────

func divider() string { return strings.Repeat("═", 64) }
func thin() string    { return strings.Repeat("─", 64) }

func printDivider()  { fmt.Println(divider()) }
func printThin()     { fmt.Println(thin()) }
func printSection(title string) {
	fmt.Println(colBold(title))
	printThin()
}

// ── Spinner ───────────────────────────────────────────────────────────────────

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner displays an animated indicator while a long operation runs.
// Use spin() to create one, then call .ok() or .fail() to resolve it.
type Spinner struct {
	label string
	done  chan struct{}
	once  sync.Once
}

// spin starts a new spinner with the given label and returns it.
func spin(label string) *Spinner {
	s := &Spinner{label: label, done: make(chan struct{})}
	go func() {
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		i := 0
		for {
			select {
			case <-s.done:
				return
			case <-t.C:
				frame := spinFrames[i%len(spinFrames)]
				if colour {
					fmt.Printf("\r  "+ansiCyan+"%s"+ansiReset+" %s   ", frame, label)
				} else {
					fmt.Printf("\r  [%s] %s   ", frame, label)
				}
				i++
			}
		}
	}()
	return s
}

// ok resolves the spinner with a success message.
func (s *Spinner) ok(msg string) {
	s.stop()
	printOK(msg)
}

// fail resolves the spinner with a failure message.
func (s *Spinner) fail(msg string) {
	s.stop()
	printFail(msg)
}

// stop clears the spinner line.
func (s *Spinner) stop() {
	s.once.Do(func() {
		close(s.done)
		time.Sleep(60 * time.Millisecond)
		fmt.Printf("\r%-72s\r", "") // overwrite with spaces then return to start
	})
}

// ── Progress bar ──────────────────────────────────────────────────────────────

const progressWidth = 28

// PrintProgress renders an in-place progress bar.
// Call it repeatedly from a goroutine; call ClearProgress() when done.
func PrintProgress(current, total int64, label string) {
	if total <= 0 {
		return
	}
	pct := float64(current) / float64(total)
	filled := int(pct * progressWidth)
	if filled > progressWidth {
		filled = progressWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", progressWidth-filled)

	if colour {
		fmt.Printf("\r  "+ansiCyan+"[%s]"+ansiReset+" %3.0f%%  %s / %s  %s   ",
			bar, pct*100, formatBytes(current), formatBytes(total), label)
	} else {
		fmt.Printf("\r  [%s] %3.0f%%  %s / %s  %s   ",
			bar, pct*100, formatBytes(current), formatBytes(total), label)
	}
}

// ClearProgress wipes the progress bar line and positions the cursor at column 0.
func ClearProgress() {
	fmt.Printf("\r%-80s\r", "")
}

// ── Byte formatter ────────────────────────────────────────────────────────────

func formatBytes(n int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case n >= GB:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(GB))
	case n >= MB:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(MB))
	case n >= KB:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(KB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// ── Banner ────────────────────────────────────────────────────────────────────

// PrintCommandBanner prints a subtle one-line header before a command runs.
func PrintCommandBanner(cmd, description string) {
	if colour {
		fmt.Printf("\n"+ansiBold+"open-trust "+ansiCyan+cmd+ansiReset+
			ansiDim+"  —  "+description+ansiReset+"\n")
		fmt.Println(thin())
	} else {
		fmt.Printf("\nopen-trust %s  —  %s\n", cmd, description)
		fmt.Println(thin())
	}
}
