package core

import (
	bpf "github.com/aquasecurity/libbpfgo"
)

type Sched struct {
	mod       *bpf.Module
	bss       *BssMap
	structOps *bpf.BPFMap
	queue     chan []byte // The map containing tasks that are queued to user space from the kernel.
	dispatch  chan []byte
}

func LoadSched(objPath string) *Sched {
	bpfModule, err := bpf.NewModuleFromFileArgs(bpf.NewModuleArgs{
		BPFObjPath:     objPath,
		KernelLogLevel: 0,
	})
	if err != nil {
		panic(err)
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}

	s := &Sched{
		mod: bpfModule,
	}

	iters := bpfModule.Iterator()
	for {
		m := iters.NextMap()
		if m == nil {
			break
		}
		if m.Name() == "main.bss" {
			s.bss = &BssMap{m}
		} else if m.Name() == "queued" {
			s.queue = make(chan []byte)
			rb, err := s.Module().InitRingBuf("queued", s.queue)
			if err != nil {
				panic(err)
			}
			rb.Poll(300)
		} else if m.Name() == "dispatched" {
			s.dispatch = make(chan []byte)
			// TODO: implement InitUserRingBuf in libbpfgo
			// _, err := s.Module().InitUserRingBuf("dispatched", s.dispatch)
			// if err != nil {
			// 	panic(err)
			// }
		}
		if m.Type().String() == "BPF_MAP_TYPE_STRUCT_OPS" {
			s.structOps = m
		}
	}

	return s
}

func (s *Sched) Attach() error {
	return s.structOps.AttachStructOps()
}

func (s *Sched) Close() {
	s.mod.Close()
}

func (s *Sched) Module() *bpf.Module {
	return s.mod
}
