package opnsense

import (
	"bufio"
	"context"
	"io"
	"os"
	"time"
)

// maxLine bounds one log line; longer lines are cut.
const maxLine = 64 << 10

// Tail follows path (OPNsense's latest.log symlinks to the file of the
// day: a new target is a new file) and calls fn for each complete line
// appended after the start. It returns when ctx ends.
func Tail(ctx context.Context, path string, poll time.Duration, fn func(line string)) {
	var f *os.File
	var fi os.FileInfo
	var r *bufio.Reader
	var partial []byte
	open := func(fromStart bool) {
		if f != nil {
			f.Close()
			f = nil
		}
		nf, err := os.Open(path)
		if err != nil {
			return
		}
		st, err := nf.Stat()
		if err != nil {
			nf.Close()
			return
		}
		if !fromStart {
			if _, err := nf.Seek(0, io.SeekEnd); err != nil {
				nf.Close()
				return
			}
		}
		f, fi, r, partial = nf, st, bufio.NewReaderSize(nf, 64<<10), nil
	}
	open(false)
	t := time.NewTicker(poll)
	defer t.Stop()
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	drain := func() bool {
		if f == nil {
			return true
		}
		for {
			chunk, err := r.ReadSlice('\n')
			if len(chunk) > 0 && len(partial)+len(chunk) <= maxLine {
				partial = append(partial, chunk...)
			}
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil {
				return true // EOF: keep the partial line for later
			}
			line := partial
			partial = nil
			if n := len(line); n > 0 && line[n-1] == '\n' {
				line = line[:n-1]
			}
			fn(string(line))
			if ctx.Err() != nil {
				return false
			}
		}
	}
	for {
		if !drain() {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st, err := os.Stat(path)
		switch {
		case err != nil:
			// The symlink is being switched: try again at the next tick.
		case f == nil:
			open(true) // appeared after the start: read it all
		case !os.SameFile(st, fi):
			// A new day's file: what is left of the old one first.
			if !drain() {
				return
			}
			open(true)
		default:
			if pos, err := f.Seek(0, io.SeekCurrent); err == nil && st.Size() < pos-int64(r.Buffered()) {
				open(true) // truncated
			}
		}
	}
}
