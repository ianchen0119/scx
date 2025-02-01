package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"encoding/binary"
	"unsafe"

	core "github.com/ianchen0119/scx/scx_goland_core/goland_core"
)

func endian() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

var taskPool []*core.QueuedTask = []*core.QueuedTask{}

func DrainQueuedTask(s *core.Sched) {
	for {
		task := s.DequeueTask()
		if task == nil {
			return
		}
		taskPool = append(taskPool, task)
	}
}

func GetTaskFromPool() *core.QueuedTask {
	if len(taskPool) == 0 {
		return nil
	}
	t := taskPool[0]
	taskPool = taskPool[1:]
	return t
}

func main() {
	bpfModule := core.LoadSched("main.bpf.o")
	defer bpfModule.Close()

	pid := os.Getpid()
	log.Printf("pid: %v", pid)
	err := bpfModule.AssignUserSchedPid(pid)
	if err != nil {
		log.Printf("AssignUserSchedPid failed: %v", err)
	}

	if err := bpfModule.Attach(); err != nil {
		log.Printf("bpfModule attach failed: %v", err)
	}

	go func() {
		for {
			DrainQueuedTask(bpfModule)
			t := GetTaskFromPool()
			if t == nil {
				continue
			}
			_, bss := bpfModule.GetBssData()
			log.Printf("bss: %v", bss)
			task := core.NewDispatchedTask(t)
			err, cpu := bpfModule.SelectCPU(t)
			if err != nil {
				log.Printf("SelectCPU failed: %v", err)
			}
			if cpu < 0 {
				cpu = core.RL_CPU_ANY
			}
			task.Cpu = int32(cpu)
			task.SliceNs = 20000000
			task.Vtime = 20000000
			log.Printf("selected task: %d, cpu: %v, old cpu: %v, dp: %v", task.Pid, cpu, t.Cpu, task)
			bpfModule.DispatchTask(task)
			bpfModule.NotifyComplete(uint64(len(taskPool)))
		}
	}()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	log.Println("receive os signal")
	log.Println("scheduler exit")
}
