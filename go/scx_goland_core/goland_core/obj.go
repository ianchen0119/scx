package core

import (
	bpf "github.com/aquasecurity/libbpfgo"
)

type Sched struct {
	mod       *bpf.Module
	bss       *BssMap
	structOps *bpf.BPFMap
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
