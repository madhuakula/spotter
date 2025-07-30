package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// ProgressBar represents a terminal progress bar
type ProgressBar struct {
	mu          sync.Mutex
	total       int
	current     int
	width       int
	prefix      string
	writer      io.Writer
	startTime   time.Time
	lastUpdate  time.Time
	updateRate  time.Duration
	finished    bool
	isTerminal  bool
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int, prefix string) *ProgressBar {
	writer := os.Stderr
	isTerminal := term.IsTerminal(int(os.Stderr.Fd()))
	
	width := 50
	if isTerminal {
		if termWidth, _, err := term.GetSize(int(os.Stderr.Fd())); err == nil {
			// Use 60% of terminal width for progress bar, with minimum of 20
			width = termWidth * 6 / 10
			if width < 20 {
				width = 20
			}
			if width > 80 {
				width = 80
			}
		}
	}

	return &ProgressBar{
		total:      total,
		current:    0,
		width:      width,
		prefix:     prefix,
		writer:     writer,
		startTime:  time.Now(),
		lastUpdate: time.Now(),
		updateRate: 100 * time.Millisecond, // Update every 100ms
		isTerminal: isTerminal,
	}
}

// Increment increases the progress by 1
func (pb *ProgressBar) Increment() {
	pb.Add(1)
}

// Add increases the progress by the specified amount
func (pb *ProgressBar) Add(n int) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.current += n
	if pb.current > pb.total {
		pb.current = pb.total
	}

	// Rate limit updates for performance
	now := time.Now()
	if now.Sub(pb.lastUpdate) >= pb.updateRate || pb.current == pb.total {
		pb.render()
		pb.lastUpdate = now
	}
}

// SetTotal updates the total count
func (pb *ProgressBar) SetTotal(total int) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.total = total
	pb.render()
}

// Finish completes the progress bar
func (pb *ProgressBar) Finish() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if pb.finished {
		return
	}

	pb.current = pb.total
	pb.finished = true
	pb.render()
	
	if pb.isTerminal {
		fmt.Fprint(pb.writer, "\n")
	}
}

// render draws the progress bar
func (pb *ProgressBar) render() {
	if !pb.isTerminal {
		// For non-terminal output, just show periodic updates
		if pb.current%10 == 0 || pb.current == pb.total {
			percentage := float64(pb.current) / float64(pb.total) * 100
			fmt.Fprintf(pb.writer, "%s: %d/%d (%.1f%%)\n", pb.prefix, pb.current, pb.total, percentage)
		}
		return
	}

	// Calculate percentage
	percentage := float64(pb.current) / float64(pb.total) * 100
	if pb.total == 0 {
		percentage = 0
	}

	// Calculate filled portion
	filledWidth := int(float64(pb.width) * float64(pb.current) / float64(pb.total))
	if pb.total == 0 {
		filledWidth = 0
	}

	// Build progress bar
	bar := strings.Repeat("█", filledWidth) + strings.Repeat("░", pb.width-filledWidth)

	// Calculate ETA
	elapsed := time.Since(pb.startTime)
	var eta string
	if pb.current > 0 && pb.current < pb.total {
		remaining := time.Duration(float64(elapsed) * float64(pb.total-pb.current) / float64(pb.current))
		eta = fmt.Sprintf(" ETA: %s", formatDuration(remaining))
	} else if pb.current == pb.total {
		eta = fmt.Sprintf(" Completed in %s", formatDuration(elapsed))
	}

	// Format output
	output := fmt.Sprintf("\r%s [%s] %d/%d (%.1f%%)%s",
		pb.prefix, bar, pb.current, pb.total, percentage, eta)

	// Clear line and write progress
	fmt.Fprint(pb.writer, "\r\033[K"+output)
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0fm%.0fs", d.Minutes(), d.Seconds()-60*d.Minutes())
	}
	return fmt.Sprintf("%.0fh%.0fm", d.Hours(), d.Minutes()-60*d.Hours())
}

// ProgressTracker manages multiple progress operations
type ProgressTracker struct {
	mu    sync.Mutex
	bars  map[string]*ProgressBar
	order []string
}

// NewProgressTracker creates a new progress tracker
func NewProgressTracker() *ProgressTracker {
	return &ProgressTracker{
		bars:  make(map[string]*ProgressBar),
		order: make([]string, 0),
	}
}

// AddBar adds a new progress bar
func (pt *ProgressTracker) AddBar(name string, total int, prefix string) *ProgressBar {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	bar := NewProgressBar(total, prefix)
	pt.bars[name] = bar
	pt.order = append(pt.order, name)
	return bar
}

// GetBar returns a progress bar by name
func (pt *ProgressTracker) GetBar(name string) *ProgressBar {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	return pt.bars[name]
}

// FinishAll finishes all progress bars
func (pt *ProgressTracker) FinishAll() {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	for _, name := range pt.order {
		if bar, exists := pt.bars[name]; exists {
			bar.Finish()
		}
	}
}