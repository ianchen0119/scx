package main

import (
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"encoding/binary"
	"unsafe"

	core "github.com/ianchen0119/scx/scx_goland_core/goland_core"
	"github.com/ianchen0119/scx/scx_goland_core/util"
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

func init() {
	runtime.GOMAXPROCS(1)
}

func main() {
	bpfModule := core.LoadSched("main.bpf.o")
	defer bpfModule.Close()
	pid := os.Getpid()
	err := bpfModule.AssignUserSchedPid(pid)
	if err != nil {
		log.Printf("AssignUserSchedPid failed: %v", err)
	}
	log.Printf("pid: %v", pid)

	topo, err := util.GetTopology()
	if err != nil {
		log.Panicf("GetTopology failed: %v", err)
	}
	log.Printf("topology: %v", topo)
	for _, cpuIdList := range topo["L2"] {
		for _, cpuId := range cpuIdList {
			for _, sibCpuId := range cpuIdList {
				err = bpfModule.EnableSiblingCpu(2, int32(cpuId), int32(sibCpuId))
				if err != nil {
					log.Panicf("EnableSiblingCpu failed: lvl %v cpuId %v sibCpuId %v", 2, cpuId, sibCpuId)
				}
			}
		}
	}

	for _, cpuIdList := range topo["L3"] {
		for _, cpuId := range cpuIdList {
			for _, sibCpuId := range cpuIdList {
				err = bpfModule.EnableSiblingCpu(3, int32(cpuId), int32(sibCpuId))
				if err != nil {
					log.Panicf("EnableSiblingCpu failed: lvl %v cpuId %v sibCpuId %v", 3, cpuId, sibCpuId)
				}
			}
		}
	}

	if err := bpfModule.Attach(); err != nil {
		log.Printf("bpfModule attach failed: %v", err)
	}

	go func() {
		for {
			DrainQueuedTask(bpfModule)
			t := GetTaskFromPool()
			if t == nil {
				runtime.Gosched()
				continue
			}
			// _, bss := bpfModule.GetBssData()
			// log.Printf("bss: %v", bss.String())
			task := core.NewDispatchedTask(t)
			err, cpu := bpfModule.SelectCPU(t)
			if err != nil {
				log.Printf("SelectCPU failed: %v", err)
			}
			if cpu < 0 {
				cpu = core.RL_CPU_ANY
			}
			task.Cpu = cpu
			task.SliceNs = 20000000
			task.Vtime = 18446744073709551615
			log.Printf("selected task: %d, cpu: %v, old cpu: %v, dp: %v", task.Pid, cpu, t.Cpu, task)
			bpfModule.DispatchTask(task)
			err = bpfModule.NotifyComplete(uint64(len(taskPool)))
			if err != nil {
				log.Printf("NotifyComplete failed: %v", err)
			}
			runtime.Gosched()
		}
	}()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	log.Println("receive os signal")
	log.Println("scheduler exit")
}
