package progress

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// ProgressBar represents a terminal progress bar
type ProgressBar struct {
	mu         sync.Mutex
	total      int
	current    int
	width      int
	prefix     string
	writer     io.Writer
	startTime  time.Time
	lastUpdate time.Time
	updateRate time.Duration
	finished   bool
	isTerminal bool
	testDelay  time.Duration // For testing purposes - can be set to slow down progress
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

	// Set test delay based on environment variable for demonstration
	testDelay := time.Duration(0)
	if delayStr := os.Getenv("SPOTTER_DEMO_DELAY_SECONDS"); delayStr != "" {
		if delaySeconds, err := strconv.Atoi(delayStr); err == nil && delaySeconds > 0 {
			testDelay = time.Duration(delaySeconds) * time.Second / time.Duration(total)
			if testDelay > 2*time.Second {
				testDelay = 2 * time.Second // Cap individual delay at 2 seconds
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
		testDelay:  testDelay,
	}
}

// SetTestDelay sets a delay for testing purposes
func (pb *ProgressBar) SetTestDelay(delay time.Duration) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.testDelay = delay
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

	// Apply test delay if set
	if pb.testDelay > 0 {
		time.Sleep(pb.testDelay)
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
		if _, err := fmt.Fprint(pb.writer, "\n"); err != nil {
			// We can't use the logger here as it might cause a recursive loop
			// if the logger is writing to the same writer
			fmt.Fprintf(os.Stderr, "Error writing progress bar newline: %v\n", err)
		}
	}
}

// render draws the progress bar
func (pb *ProgressBar) render() {
	if !pb.isTerminal {
		// For non-terminal output, just show periodic updates
		if pb.current%10 == 0 || pb.current == pb.total {
			if _, err := fmt.Fprintf(pb.writer, "%s: %d/%d\n", pb.prefix, pb.current, pb.total); err != nil {
				// We can't use the logger here as it might cause a recursive loop
				// if the logger is writing to the same writer
				fmt.Fprintf(os.Stderr, "Error writing progress update: %v\n", err)
			}
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

	// Build progress bar with nice characters
	filled := strings.Repeat("█", filledWidth)
	empty := strings.Repeat("░", pb.width-filledWidth)
	bar := filled + empty

	// Calculate ETA
	elapsed := time.Since(pb.startTime)
	var eta string
	if pb.current > 0 && pb.current < pb.total {
		remaining := time.Duration(float64(elapsed) * float64(pb.total-pb.current) / float64(pb.current))
		eta = fmt.Sprintf(" ETA: %s", formatDuration(remaining))
	} else if pb.current == pb.total {
		eta = fmt.Sprintf(" Completed in %s", formatDuration(elapsed))
	}

	// Format output with nice progress bar
	output := fmt.Sprintf("\r%s [%s] %d/%d (%.1f%%)%s",
		pb.prefix, bar, pb.current, pb.total, percentage, eta)

	// Clear line and write progress
	if _, err := fmt.Fprint(pb.writer, "\r\033[K"+output); err != nil {
		// We can't use the logger here as it might cause a recursive loop
		// if the logger is writing to the same writer
		fmt.Fprintf(os.Stderr, "Error writing progress bar: %v\n", err)
	}
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

// GetBar retrieves a progress bar by name
func (pt *ProgressTracker) GetBar(name string) (*ProgressBar, bool) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	bar, exists := pt.bars[name]
	return bar, exists
}

// FinishAll completes all progress bars
func (pt *ProgressTracker) FinishAll() {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	for _, name := range pt.order {
		if bar, exists := pt.bars[name]; exists {
			bar.Finish()
		}
	}
}

// Clear removes all progress bars
func (pt *ProgressTracker) Clear() {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.bars = make(map[string]*ProgressBar)
	pt.order = make([]string, 0)
}
