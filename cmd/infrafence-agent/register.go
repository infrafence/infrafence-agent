package main

import (
	"bufio"
	"errors"
	"io"
	"runtime"
	"strings"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/platform"
)

// parseRegisterArgs reads "register" arguments: the original
// "<server_url> <agent_name> <install_token>", or with --token-stdin the
// token from stdin (one line), so it never shows in the process list.
// --mode protect|monitor is the mode picked at install (appliances).
func parseRegisterArgs(args []string, stdin io.Reader) (serverURL, name, token, mode string, err error) {
	var pos []string
	fromStdin := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--token-stdin":
			fromStdin = true
		case a == "--mode" && i+1 < len(args):
			mode = args[i+1]
			i++
		case strings.HasPrefix(a, "--mode="):
			mode = strings.TrimPrefix(a, "--mode=")
		default:
			pos = append(pos, a)
		}
	}
	if mode != "" && mode != "protect" && mode != "monitor" {
		return "", "", "", "", errors.New("--mode must be protect or monitor")
	}
	if fromStdin {
		if len(pos) < 2 {
			return "", "", "", "", errors.New("missing server URL or agent name")
		}
		line, rerr := bufio.NewReader(io.LimitReader(stdin, 1024)).ReadString('\n')
		if rerr != nil && rerr != io.EOF {
			return "", "", "", "", errors.New("could not read the install token from stdin")
		}
		token = strings.TrimSpace(line)
		if token == "" {
			return "", "", "", "", errors.New("no install token on stdin")
		}
		return pos[0], pos[1], token, mode, nil
	}
	if len(pos) < 3 {
		return "", "", "", "", errors.New("missing arguments")
	}
	return pos[0], pos[1], pos[2], mode, nil
}

// applianceRegister completes the registration of the appliance build
// (FreeBSD): kind, product and mode. On Linux it changes nothing and
// returns "".
func applianceRegister(req *api.RegisterRequest, mode string) string {
	if runtime.GOOS != "freebsd" {
		return ""
	}
	return fillApplianceRegister(req, mode, platform.Detect("/", platform.FreeBSDKernel))
}

func fillApplianceRegister(req *api.RegisterRequest, mode string, info platform.Info) string {
	req.Mode = mode
	req.Platform = &api.Platform{Product: info.Product, Version: info.Version, Kernel: info.Kernel, Arch: info.Arch, ABI: info.ABI}
	if info.Kind == platform.KindOPNsense {
		req.Kind = platform.KindOPNsense
		req.OS = "opnsense"
		req.OSVersion = info.Version
		return platform.KindOPNsense
	}
	req.OS = "freebsd"
	req.OSVersion = info.Kernel
	req.Kind = platform.KindOPNsense // the appliance agent, on plain FreeBSD pf
	req.Platform.Product = "FreeBSD"
	return platform.KindOPNsense
}

// applianceRegisterIsNoop: this build registers as the server agent.
func applianceRegisterIsNoop() bool { return runtime.GOOS != "freebsd" }
