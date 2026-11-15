#!/usr/bin/env python3
"""Drives the OPNsense VM's serial console (QEMU -serial unix:SOCKET,server).

  console.py SOCKET boot           first boot: assign the interfaces (vtnet1
                                   WAN, vtnet0 LAN), log in, open a shell
  console.py SOCKET login          after a reboot: log in, open a shell
  console.py SOCKET run CMD [SECS] run CMD in that shell, print its output and
                                   exit with its status

Standard library only. All console output is appended to console.log next
to the socket.
"""
import os
import re
import socket
import sys
import time

PROMPT = "IFPROMPT# "


class Console:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(path)
        self.s.settimeout(0.5)
        self.buf = ""
        logdir = os.path.dirname(os.path.abspath(path))
        self.log = open(os.path.join(logdir, "console.log"), "a", errors="replace")

    def line(self, text):
        # One character at a time: the emulated UART drops bursts.
        for ch in text + "\r":
            self.s.sendall(ch.encode())
            time.sleep(0.003)

    def expect(self, patterns, timeout):
        """Waits for one of the regexps; returns (index, text before, match)."""
        if isinstance(patterns, str):
            patterns = [patterns]
        regs = [re.compile(p, re.M) for p in patterns]
        end = time.time() + timeout
        while True:
            for i, r in enumerate(regs):
                m = r.search(self.buf)
                if m:
                    before = self.buf[: m.start()]
                    self.buf = self.buf[m.end():]
                    return i, before, m
            if time.time() > end:
                raise TimeoutError("waiting for %r; last output:\n%s" % (patterns, self.buf[-3000:]))
            try:
                data = self.s.recv(65536)
            except socket.timeout:
                continue
            if not data:
                raise EOFError("console closed")
            text = data.decode(errors="replace").replace("\r", "")
            self.log.write(text)
            self.log.flush()
            self.buf = (self.buf + text)[-(1 << 20):]

    def shell(self):
        """From the login prompt to /bin/sh with a known prompt."""
        self.line("root")
        i, _, _ = self.expect([r"Password:", r"Enter an option:"], 120)
        if i == 0:
            self.line(os.environ.get("OPN_PASSWORD", "opnsense"))
            self.expect(r"Enter an option:", 300)
        self.line("8")
        self.expect([r"#\s*$", r"\$\s*$"], 120)
        time.sleep(1)
        self.line("exec /bin/sh")
        time.sleep(2)
        self.line("PS1='%s'; export PS1; stty -echo" % PROMPT)
        self.expect(re.escape(PROMPT), 60)

    def run(self, cmd, timeout):
        mark = "IFDONE%d" % int(time.time() * 1000)
        self.buf = ""
        self.line("( %s ) 2>&1; echo %s:$?" % (cmd, mark))
        _, out, m = self.expect(r"^%s:(\d+)$" % mark, timeout)
        lines = [l for l in out.split("\n") if mark not in l]
        return int(m.group(1)), "\n".join(lines).replace(PROMPT, "").strip("\n")


def first_boot(c):
    """First boot of the nano image: its config names NICs that do not exist
    (mismatch0/1), so the console asks for the assignment."""
    while True:
        i, _, _ = c.expect([
            r"Do you want to configure LAGGs now\? \[y/N\]",
            r"Do you want to configure VLANs now\? \[y/N\]",
            r"Enter the WAN interface name",
            r"Enter the LAN interface name",
            r"Enter the Optional interface 1 name",
            r"Do you want to proceed\? \[y/N\]",
            r"login: *$",
        ], 2400)
        if i in (0, 1):
            c.line("n")
        elif i == 2:
            c.line("vtnet1")
        elif i == 3:
            c.line("vtnet0")
        elif i == 4:
            c.line("")
        elif i == 5:
            c.line("y")
        else:
            return


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    c = Console(sys.argv[1])
    what = sys.argv[2]
    if what == "boot":
        first_boot(c)
        c.shell()
        return 0
    if what == "login":
        # The prompt may have been printed before we connected: a newline
        # makes getty print it again.
        end = time.time() + 2400
        while True:
            try:
                c.expect(r"login: *$", 30)
                break
            except TimeoutError:
                if time.time() > end:
                    raise
                c.line("")
        c.shell()
        return 0
    if what == "run":
        timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 300
        rc, out = c.run(sys.argv[3], timeout)
        if out:
            print(out)
        return rc
    print("unknown command %s" % what, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
