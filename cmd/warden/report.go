package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/calasdan-sketch/warden/internal/join"
)

func (a *app) cmdReport(args []string) int {
	fs := newFlagSet("report")
	from := fs.String("from", "", "shortleash|planok|mcp-jail|calas-gateway")
	file := fs.String("file", "", "JSONL file to ingest")
	watch := fs.Bool("watch", false, "keep tailing the file for new lines")
	if !parseArgs(fs, args) {
		return 2
	}
	var source join.Source
	switch *from {
	case "shortleash":
		source = join.SourceShortleash
	case "planok":
		source = join.SourcePlanok
	case "mcp-jail":
		source = join.SourceMCPJail
	case "calas-gateway":
		source = join.SourceCalasGateway
	default:
		fmt.Fprintln(os.Stderr, "report: --from must be shortleash|planok|mcp-jail|calas-gateway")
		return 2
	}
	if *file == "" {
		fmt.Fprintln(os.Stderr, "report: --file is required")
		return 2
	}
	n, err := a.import_.ImportFile(source, *file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "report:", err)
		return 1
	}
	fmt.Printf("imported %d records from %s (%s)\n", n, *file, source)
	if !*watch {
		return 0
	}
	// Tail for new lines until interrupted.
	fmt.Println("watching for new lines… (Ctrl+C to stop)")
	offset := fileSize(*file)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-sigs:
			return 0
		case <-tick.C:
			n, newOffset, err := tailNew(a, source, *file, offset)
			if err != nil {
				fmt.Fprintln(os.Stderr, "report:", err)
				continue
			}
			offset = newOffset
			if n > 0 {
				fmt.Printf("imported %d new records\n", n)
			}
		}
	}
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func tailNew(a *app, source join.Source, path string, offset int64) (int, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, offset, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, 0); err != nil {
		return 0, offset, err
	}
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		// Track the byte offset manually: len(line)+1 for the newline.
		offset += int64(len(line)) + 1
		if err := a.import_.ImportLine(source, line); err != nil {
			return n, offset, err
		}
		n++
	}
	return n, offset, sc.Err()
}
