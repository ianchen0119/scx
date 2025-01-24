module github.com/ianchen0119/scx/scx_goland_core

go 1.22.6

require github.com/aquasecurity/libbpfgo v0.8.0-libbpf-1.5

require (
	github.com/cilium/ebpf v0.17.1 // indirect
	golang.org/x/sys v0.26.0 // indirect
)

replace github.com/aquasecurity/libbpfgo => ./libbpfgo
