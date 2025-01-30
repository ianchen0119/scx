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
			task := bpfModule.GetTaskFromQueue()
			if task != nil {
				dispatchedTask := core.NewDispatchedTask(task)
				bpfModule.DispatchTask(dispatchedTask)
			}
		}
	}()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	log.Println("receive os signal")
	log.Println("scheduler exit")
}
