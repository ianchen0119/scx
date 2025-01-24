package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"encoding/binary"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
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
	bpfModule, err := bpf.NewModuleFromFileArgs(bpf.NewModuleArgs{
		BPFObjPath:     "scx_goland_simple.bpf.o",
		KernelLogLevel: 0,
	})
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}

	m := bpfModule

	iters := m.Iterator()
	for {
		m := iters.NextMap()
		if m == nil {
			break
		}
		if m.Type().String() == "BPF_MAP_TYPE_STRUCT_OPS" {
			if err := m.AttachStructOps(); err != nil {
				log.Printf("error: %v", err)
			}
		}
	}

	if statsMap, err := bpfModule.GetMap("stats"); err != nil {
		log.Printf("error: %v", err)
	} else {
		var wg sync.WaitGroup
		ctx, cancel := context.WithCancel(context.Background())
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
		wg.Add(1)
		go func(ctx context.Context) {
			for true {
				select {
				case <-ctx.Done():
					wg.Done()
					return
				default:
					res := getStat(statsMap)
					log.Printf("local: %d, global: %d", res[0], res[1])
				}
				time.Sleep(1 * time.Second)
			}
		}(ctx)
		<-signalChan
		log.Println("receive os signal")
		cancel()
		wg.Wait()
		log.Println("scheduler exit")
	}
}

func getStat(m *bpf.BPFMap) []uint64 {
	cpuNum, err := bpf.NumPossibleCPUs()
	if err != nil {
		log.Fatal(err)
	}
	var cnts [][]uint64 = make([][]uint64, 2)
	cnts[0] = make([]uint64, cpuNum)
	cnts[1] = make([]uint64, cpuNum)
	stats := []uint64{0, 0}
	for i := 0; i < 2; i++ {
		v, err := m.GetValue(unsafe.Pointer(&i))
		if err != nil {
			log.Fatal(err)
		}
		for cpu := 0; cpu < cpuNum; cpu++ {
			n := v[cpu*8 : cpu*8+8]
			cnts[i][cpu] = endian().Uint64(n)
			stats[i] += cnts[i][cpu]
		}
	}
	return stats
}
