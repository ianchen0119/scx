package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"
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

func init() {
	unix.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE)
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
		prog := iters.NextProgram()
		if prog == nil {
			break
		}
		if prog.Name() == "kprobe_handle_mm_fault" {
			log.Println("attach kprobe_handle_mm_fault")
			_, err := prog.AttachGeneric()
			if err != nil {
				log.Panicf("attach kprobe_handle_mm_fault failed: %v", err)
			}
			continue
		}
		if prog.Name() == "kretprobe_handle_mm_fault" {
			log.Println("attach kretprobe_handle_mm_fault")
			_, err := prog.AttachGeneric()
			if err != nil {
				log.Panicf("attach kretprobe_handle_mm_fault failed: %v", err)
			}
			continue
		}
	}
	iters = bpfModule.Iterator()
	for {
		m := iters.NextMap()
		if m == nil {
			break
		}
		if m.Name() == "main.bss" {
			s.bss = &BssMap{m}
		} else if m.Name() == "queued" {
			s.queue = make(chan []byte, 200)
			rb, err := s.mod.InitRingBuf("queued", s.queue)
			if err != nil {
				panic(err)
			}
			rb.Poll(300)
		} else if m.Name() == "dispatched" {
			s.dispatch = make(chan []byte, 200)
			urb, err := s.mod.InitUserRingBuf("dispatched", s.dispatch)
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

func (s *Sched) SelectCPU(t *QueuedTask) (error, int32) {
	if s.selectCpu != nil {
		arg := &task_cpu_arg{
			pid:   t.Pid,
			cpu:   t.Cpu,
			flags: t.Flags,
		}
		var data bytes.Buffer
		binary.Write(&data, binary.LittleEndian, arg)
		opt := bpf.RunOpts{
			CtxIn:     data.Bytes(),
			CtxSizeIn: uint32(data.Len()),
		}
		err := s.selectCpu.Run(&opt)
		if err != nil {
			return err, 0
		}
		if opt.RetVal > 2147483647 {
			return nil, -1
		}
		return nil, int32(opt.RetVal)
	}
	return fmt.Errorf("prog (selectCpu) not found"), 0
}

type domain_arg struct {
	lvlId        int32
	cpuId        int32
	siblingCpuId int32
}

func (s *Sched) EnableSiblingCpu(lvlId, cpuId, siblingCpuId int32) error {
	if s.siblingCpu != nil {
		arg := &domain_arg{
			lvlId:        lvlId,
			cpuId:        cpuId,
			siblingCpuId: siblingCpuId,
		}
		var data bytes.Buffer
		binary.Write(&data, binary.LittleEndian, arg)
		opt := bpf.RunOpts{
			CtxIn:     data.Bytes(),
			CtxSizeIn: uint32(data.Len()),
		}
		err := s.siblingCpu.Run(&opt)
		if err != nil {
			return err
		}
		if opt.RetVal != 0 {
			return fmt.Errorf("retVal: %v", opt.RetVal)
		}
		return nil
	}
	return fmt.Errorf("prog (siblingCpu) not found")
}

func (s *Sched) Attach() error {
	return s.structOps.AttachStructOps()
}

func (s *Sched) Close() {
	s.mod.Close()
}
