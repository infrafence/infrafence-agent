package scanwatch

import "golang.org/x/net/bpf"

// SYNFilter is the classic BPF program run in the kernel: only TCP segments
// with SYN set and ACK clear — new connection attempts — reach the agent
// (IPv4 without fragments, IPv6 without extension headers); everything else
// is dropped before copying. Packets start at the IP header (SOCK_DGRAM).
func SYNFilter() []bpf.Instruction {
	return []bpf.Instruction{
		/*  0 */ bpf.LoadAbsolute{Off: 0, Size: 1}, // version nibble
		/*  1 */ bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 4},
		/*  2 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 4, SkipTrue: 1}, // IPv4 -> 4
		/*  3 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 8, SkipFalse: 13}, // IPv6 -> 12, else drop
		/*  4 */ bpf.LoadAbsolute{Off: 9, Size: 1}, // IPv4 protocol
		/*  5 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipFalse: 11}, // TCP? else drop
		/*  6 */ bpf.LoadAbsolute{Off: 6, Size: 2}, // flags + fragment offset
		/*  7 */ bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 9}, // fragment -> drop
		/*  8 */ bpf.LoadMemShift{Off: 0}, // X = IPv4 header length
		/*  9 */ bpf.LoadIndirect{Off: 13, Size: 1}, // TCP flags
		/* 10 */ bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x12}, // SYN|ACK
		/* 11 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x02, SkipTrue: 6, SkipFalse: 5}, // SYN only -> accept
		/* 12 */ bpf.LoadAbsolute{Off: 6, Size: 1}, // IPv6 next header
		/* 13 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipFalse: 3}, // TCP? else drop
		/* 14 */ bpf.LoadAbsolute{Off: 40 + 13, Size: 1}, // TCP flags
		/* 15 */ bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x12},
		/* 16 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x02, SkipTrue: 1}, // SYN only -> accept
		/* 17 */ bpf.RetConstant{Val: 0}, // drop
		/* 18 */ bpf.RetConstant{Val: 96}, // accept (headers only)
	}
}
