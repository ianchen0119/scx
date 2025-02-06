package util

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func parseCPUs(cpuList string) ([]int, error) {
	var result []int
	segments := strings.Split(cpuList, ",")

	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if strings.Contains(segment, "-") {
			bounds := strings.Split(segment, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid range: %s", segment)
			}

			start, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("invalid start of range: %s", bounds[0])
			}

			end, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid end of range: %s", bounds[1])
			}

			if start > end {
				return nil, fmt.Errorf("start greater than end in range: %s", segment)
			}
			for i := start; i <= end; i++ {
				result = append(result, i)
			}
		} else {
			num, err := strconv.Atoi(segment)
			if err != nil {
				return nil, fmt.Errorf("invalid number: %s", segment)
			}
			result = append(result, num)
		}
	}

	return result, nil
}

func GetTopology() (map[string]map[string][]int, error) {
	cacheDir := "/sys/devices/system/cpu/"
	cacheMap := map[string]map[string][]int{
		"L2": map[string][]int{},
		"L3": map[string][]int{},
	}

	err := filepath.Walk(cacheDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		var content []byte
		var key string
		if strings.HasSuffix(path, "shared_cpu_list") {
			if strings.Contains(path, "/cache/index2/") {
				content, err = os.ReadFile(path)
				if err != nil {
					return err
				}
				key = "L2"

			} else if strings.Contains(path, "/cache/index3/") {
				content, err = os.ReadFile(path)
				if err != nil {
					return err
				}
				key = "L3"
			}
			cpuIdList, err := parseCPUs(strings.TrimSpace(string(content)))
			if err != nil {
				return nil
			}
			cacheMap[key][strings.TrimSpace(string(content))] = cpuIdList
		}
		return nil
	})

	if err != nil {
		return cacheMap, err
	}

	return cacheMap, nil
}
