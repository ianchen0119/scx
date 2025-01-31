package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	RL_CPU_ANY = 1 << 20
)

type Sched struct {
	mod        *bpf.Module
	bss        *BssMap
	structOps  *bpf.BPFMap
	queue      chan []byte // The map containing tasks that are queued to user space from the kernel.
	dispatch   chan []byte
	selectCpu  *bpf.BPFProg
	siblingCpu *bpf.BPFProg
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
			urb, err := s.Module().InitUserRingBuf("dispatched", s.dispatch)
			if err != nil {
				panic(err)
			}
			urb.Start()
		}
		if m.Type().String() == "BPF_MAP_TYPE_STRUCT_OPS" {
			s.structOps = m
		}
	}

	iters = bpfModule.Iterator()
	for {
		prog := iters.NextProgram()
		if prog == nil {
			break
		}

		if prog.Name() == "rs_select_cpu" {
			s.selectCpu = prog
		}

		if prog.Name() == "enable_sibling_cpu" {
			s.siblingCpu = prog
		}
	}

	return s
}

type task_cpu_arg struct {
	pid   int32
	cpu   int32
	flags uint64
}

func (s *Sched) SelectCPU(t *QueuedTask) error {
	if s.selectCpu != nil {
		arg := &task_cpu_arg{
			pid:   t.Pid,
			cpu:   t.Cpu,
			flags: t.Flags,
		}
		var data bytes.Buffer
		binary.Write(&data, binary.LittleEndian, arg)
		opt := bpf.RunOpts{
			CtxIn: data.Bytes(),
		}
		err := s.selectCpu.Run(&opt)
		if err != nil {
			log.Println(err)
			return err
		}
		log.Println(opt.RetVal)
		return nil
	}
	return fmt.Errorf("selectCpu not found")
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
