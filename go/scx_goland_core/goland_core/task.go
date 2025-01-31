package core

import (
	"bytes"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
)

// Task queued for scheduling from the BPF component (see bpf_intf::queued_task_ctx).
type QueuedTask struct {
	Pid            int32  // pid that uniquely identifies a task
	Cpu            int32  // CPU where the task is running
	Flags          uint64 // task enqueue flags
	SumExecRuntime uint64 // Total cpu time
	Nvcsw          uint64 // Total amount of voluntary context switches
	Weight         uint64 // Task static priority
	Slice          uint64 // Time slice budget
	Vtime          uint64 // Current vruntime
	CpuMaskCnt     uint64 // cpumask generation counter (private)
}

func (s *Sched) GetTaskFromQueue() *QueuedTask {
	t := <-s.queue
	task := QueuedTask{}
	buff := bytes.NewBuffer(t)
	err := binary.Read(buff, binary.LittleEndian, &task)
	if err != nil {
		return nil
	}
	return &task
}

// Task queued for dispatching to the BPF component (see bpf_intf::dispatched_task_ctx).
type DispatchedTask struct {
	Pid        int32  // pid that uniquely identifies a task
	Cpu        int32  // target CPU selected by the scheduler
	Flags      uint64 // special dispatch flags
	SliceNs    uint64 // time slice assigned to the task (0 = default)
	Vtime      uint64 // task deadline / vruntime
	cpuMaskCnt uint64 // cpumask generation counter (private)
}

// NewDispatchedTask creates a DispatchedTask from a QueuedTask.
func NewDispatchedTask(task *QueuedTask) *DispatchedTask {
	return &DispatchedTask{
		Pid:        task.Pid,
		Cpu:        task.Cpu,
		Flags:      task.Flags,
		SliceNs:    0, // use default time slice
		Vtime:      0,
		cpuMaskCnt: task.CpuMaskCnt,
	}
}

func (s *Sched) DispatchTask(t *DispatchedTask) {
	var task bytes.Buffer // Stand-in for a network connection
	// enc := gob.NewEncoder(&task) // Will write to network.
	// // Encode (send) the value.
	// err := enc.Encode(t)
	// if err != nil {
	// 	log.Fatal("encode error:", err)
	// }
	binary.Write(&task, binary.LittleEndian, t)
	s.dispatch <- task.Bytes()
}

func IsSMTActive() (bool, error) {
	data, err := os.ReadFile("/sys/devices/system/cpu/smt/active")
	if err != nil {
		return false, err
	}

	contents := strings.TrimSpace(string(data))
	smtActive, err := strconv.Atoi(contents)
	if err != nil {
		return false, err
	}

	return smtActive == 1, nil
}
