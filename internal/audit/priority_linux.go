package audit

import (
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// nicedEnv marks the process started again at a low priority.
const nicedEnv = "INFRAFENCE_AUDIT_NICED"

// LowerPriority starts the audit again at nice 10 and the lowest
// best-effort I/O priority, so it never competes with the server's work.
// Linux keeps these per thread: the calling thread sets them and execs,
// and the new process (and every command it runs) inherits them. When it
// can't, the audit runs as it is.
func LowerPriority() {
	if os.Getenv(nicedEnv) == "1" {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10); err != nil {
		return
	}
	// IOPRIO_WHO_PROCESS, this thread, class best-effort (2) level 7.
	_, _, _ = unix.Syscall(unix.SYS_IOPRIO_SET, 1, 0, uintptr(2<<13|7))
	_ = syscall.Exec("/proc/self/exe", os.Args, append(os.Environ(), nicedEnv+"=1"))
}
