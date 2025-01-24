package core

import (
	"fmt"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

type BssData struct {
	Usersched_pid        uint32
	paid                 uint32
	Nr_queued            uint64
	Nr_scheduled         uint64
	Nr_running           uint64
	Nr_online_cpus       uint64
	Nr_user_dispatches   uint64
	Nr_kernel_dispatches uint64
	Nr_cancel_dispatches uint64
	Nr_bounce_dispatches uint64
	Nr_failed_dispatches uint64
	Nr_sched_congested   uint64
}

type BssMap struct {
	*bpf.BPFMap
}

func (s *Sched) AssignUserSchedPid(pid int) error {
	if s.bss == nil {
		return fmt.Errorf("BssMap is nil")
	}
	i := 0
	return s.bss.BPFMap.Update(unsafe.Pointer(&i), unsafe.Pointer(&BssData{
		Usersched_pid: uint32(pid),
	}))
}
