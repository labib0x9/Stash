package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type Region struct {
	Start   uint64 `json:"start"`
	End     uint64 `json:"end"`
	Perms   string `json:"perms"`
	Path    string `json:"path"`
	content []byte
}

type Status struct {
	Name    string   `json:"name"`
	Thread  int      `json:"thread"`
	Region  []Region `json:"region"`
	CmdLine string   `json:"cmds"`
	EnvRaw  string
	Env     []string `json:"env"`
	Cwd     string   `json:"cwd"`
}

func main() {

	var stat Status
	stat.Region = make([]Region, 0, 10)

	args := os.Args
	if len(args) != 2 {
		return
	}

	pid := args[1]

	status, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		panic(err)
	}
	splitted := bytes.Split(status, []byte("\n"))
	for _, s := range splitted {
		if strings.HasPrefix(string(s), "Name") {
			name := strings.TrimSpace(strings.TrimPrefix(string(s), "Name:"))
			stat.Name = name
		} else if strings.HasPrefix(string(s), "Threads") {
			thread := strings.TrimSpace(strings.TrimPrefix(string(s), "Threads:"))
			threadInt, err := strconv.ParseInt(thread, 10, 32)
			if err != nil {
				panic(err)
			}
			stat.Thread = int(threadInt)
		}
	}
	fmt.Println(stat)
	if stat.Thread != 1 {
		panic("Must be single threaded")
	}

	memFile, err := os.Open("/proc/" + pid + "/maps")
	if err != nil {
		panic(err)
	}
	defer memFile.Close()

	scanner := bufio.NewScanner(memFile)
	prev := ""

	for scanner.Scan() {
		line := scanner.Text()
		splitLine := strings.Fields(line)

		addrs := strings.Split(splitLine[0], "-")
		start, _ := strconv.ParseUint(addrs[0], 16, 64)
		end, _ := strconv.ParseUint(addrs[1], 16, 64)

		perms := splitLine[1]

		path := ""
		if len(splitLine) >= 6 {
			path = splitLine[5]
		}

		if strings.Contains(path, "stack") && strings.HasPrefix(perms, "rw") {
			stat.Region = append(stat.Region, Region{Start: start, End: end, Perms: perms, Path: path})
		} else if strings.Contains(path, stat.Name) && strings.HasPrefix(perms, "rw") {
			stat.Region = append(stat.Region, Region{Start: start, End: end, Perms: perms, Path: path})
		} else if path == "" && strings.Contains(prev, stat.Name) && strings.HasPrefix(perms, "rw") {
			stat.Region = append(stat.Region, Region{Start: start, End: end, Perms: perms, Path: path})

		}

		prev = path
	}

	fmt.Println("PREV READ", stat)

	memByteFile, err := os.Open("/proc/" + pid + "/mem")
	if err != nil {
		panic(err)
	}
	defer memByteFile.Close()
	for i, reg := range stat.Region {
		start := reg.Start
		end := reg.End
		_, err := memByteFile.Seek(int64(start), 0)
		if err != nil {
			panic(err)
		}
		content := make([]byte, end-start)
		n, err := io.ReadFull(memByteFile, content)
		if err != nil {
			panic(err)
		}
		fmt.Println(n, "byte read.")
		stat.Region[i].content = make([]byte, len(content))
		copy(stat.Region[i].content, content)
	}

	cmdline, err := os.ReadFile("/proc/" + pid + "/cmdline")
	if err != nil {
		panic(err)
	}

	stat.CmdLine = string(cmdline)
	// copy(stat.CmdLine, cmdline)

	fmt.Println(string(stat.CmdLine))

	environ, err := os.ReadFile("/proc/" + pid + "/environ")
	if err != nil {
		panic(err)
	}

	stat.EnvRaw = string(environ)
	// copy(stat.EnvRaw, environ)

	environSplit := bytes.Split(environ, []byte{'\x00'})
	stat.Env = make([]string, len(environSplit))
	for i, env := range environSplit {
		// stat.Env[i] = make([]byte, len(env))
		// copy(stat.Env[i], env)
		stat.Env[i] = string(env)
	}
	fmt.Println(string(stat.Env[0]))
	fmt.Println(string(stat.EnvRaw))

	cwd, err := os.Readlink("/proc/" + pid + "/cwd")
	if err != nil {
		panic(err)
	}

	stat.Cwd = cwd
	fmt.Println(stat.Cwd)

	fmt.Println("SAVING")
	if err := Save(stat); err != nil {
		panic(err)
	}
}

func Save(stat Status) error {
	f, err := os.OpenFile("checkpoint.json", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	if err := encoder.Encode(stat); err != nil {
		panic(err)
	}

	os.MkdirAll("region", 0755)

	for _, reg := range stat.Region {
		name := fmt.Sprintf("%x-%x.bin", reg.Start, reg.End)
		f, err := os.OpenFile("region/"+name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		n, err := f.Write(reg.content)
		if err != nil {
			panic(err)
		}
		if n != len(reg.content) {
			panic("length mismatch")
		}
	}

	return nil
}
