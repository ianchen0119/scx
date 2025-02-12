package main

import (
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
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

const (
	MAX_LATENCY_WEIGHT = 1000
	SLICE_NS_MIN       = 500 * 1000  // 500us
	SLICE_NS_DEFAULT   = 5000 * 1000 // 5ms
	SCX_ENQ_WAKEUP     = 1
)

func calcLatencyWeight(nvcsw uint64, flags uint64) uint64 {
	baseWeight := min(nvcsw, MAX_LATENCY_WEIGHT)
	weightMultiplier := uint64(1)
	if flags&SCX_ENQ_WAKEUP != 0 {
		weightMultiplier = 2
	}
	return (baseWeight * weightMultiplier) + 1
}

func calcSliceNs(queueLen int, latencyWeight uint64) uint64 {
	// 基本時間片
	waiting := uint64(queueLen + 1)
	baseSlice := SLICE_NS_DEFAULT / waiting

	// 根據 latency weight 調整時間片
	slice := baseSlice * latencyWeight / MAX_LATENCY_WEIGHT

	return max(slice, SLICE_NS_MIN)
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
	debug.SetMaxThreads(10)
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
				err = bpfModule.NotifyComplete(uint64(len(taskPool)))
				if err != nil {
					log.Printf("NotifyComplete failed: %v", err)
				}
				runtime.Gosched()
				continue
			}
			task := core.NewDispatchedTask(t)
			err, cpu := bpfModule.SelectCPU(t)
			if err != nil {
				log.Printf("SelectCPU failed: %v", err)
			}
			if cpu < 0 {
				cpu = core.RL_CPU_ANY
			}

			latencyWeight := calcLatencyWeight(t.Nvcsw, t.Flags)
			task.SliceNs = calcSliceNs(len(taskPool), latencyWeight)

			vslice := task.SliceNs * 100 / t.Weight
			task.Vtime = t.Vtime + vslice
			log.Printf("selected task: %d, cpu: %v, sliceNs: %v, weight: %v, nvcsw: %v",
				task.Pid, cpu, task.SliceNs, t.Weight, t.Nvcsw)
			bpfModule.DispatchTask(task)
		}
	}()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	log.Println("receive os signal")
	log.Println("scheduler exit")
}
