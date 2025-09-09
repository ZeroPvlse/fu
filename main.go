package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Token string
type TokenSlice []Token

type TokStruct struct {
	// file operations
	Write  Token
	Read   Token
	Delete Token
	Copy   Token
	Move   Token

	// output
	Print Token
	Log   Token

	// system
	Exec  Token
	Sleep Token
	Loop  Token

	// network
	Ping     Token
	Scan     Token
	Http     Token
	Download Token

	// crypto/encoding
	Hash   Token
	Encode Token
	Decode Token

	// variables & logic
	Set Token
	If  Token

	// process & system info
	Kill    Token
	Ps      Token
	Sysinfo Token

	// file analysis
	Find Token
	Grep Token
	Size Token

	// network analysis
	Nslookup Token
	Whois    Token

	// advanced
	Zip   Token
	Unzip Token
	Chmod Token
}

const (
	WRITE  Token = "write"
	READ   Token = "read"
	DELETE Token = "delete"
	COPY   Token = "copy"
	MOVE   Token = "move"

	PRINT Token = "print"
	LOG   Token = "log"

	EXEC  Token = "exec"
	SLEEP Token = "sleep"
	LOOP  Token = "loop"

	PING     Token = "ping"
	SCAN     Token = "scan"
	HTTP     Token = "http"
	DOWNLOAD Token = "download"

	HASH   Token = "hash"
	ENCODE Token = "encode"
	DECODE Token = "decode"

	SET Token = "set"
	IF  Token = "if"

	KILL    Token = "kill"
	PS      Token = "ps"
	SYSINFO Token = "sysinfo"

	FIND Token = "find"
	GREP Token = "grep"
	SIZE Token = "size"

	NSLOOKUP Token = "nslookup"
	WHOIS    Token = "whois"

	ZIP   Token = "zip"
	UNZIP Token = "unzip"
	CHMOD Token = "chmod"

	FileSuffix string = ".fu"
)

var ValidTokens = TokenSlice{
	WRITE, READ, DELETE, COPY, MOVE,
	PRINT, LOG,
	EXEC, SLEEP, LOOP,
	PING, SCAN, HTTP, DOWNLOAD,
	HASH, ENCODE, DECODE,
	SET, IF,
	KILL, PS, SYSINFO,
	FIND, GREP, SIZE,
	NSLOOKUP, WHOIS,
	ZIP, UNZIP, CHMOD,
}

var variables = make(map[string]string)

const (
	ErrInvalidArgUsage int = iota + 1
	ErrReadFromFile
	ErrTokenizerErr
	ErrExecutionErr
)

func init() {
	if err := canFuckignRun(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "err: %v\n", err)
		os.Exit(ErrInvalidArgUsage)
	}
}

func main() {
	tokensStruct := TokStruct{
		Write: WRITE, Read: READ, Delete: DELETE, Copy: COPY, Move: MOVE,
		Print: PRINT, Log: LOG,
		Exec: EXEC, Sleep: SLEEP, Loop: LOOP,
		Ping: PING, Scan: SCAN, Http: HTTP, Download: DOWNLOAD,
		Hash: HASH, Encode: ENCODE, Decode: DECODE,
		Set: SET, If: IF,
		Kill: KILL, Ps: PS, Sysinfo: SYSINFO,
		Find: FIND, Grep: GREP, Size: SIZE,
		Nslookup: NSLOOKUP, Whois: WHOIS,
		Zip: ZIP, Unzip: UNZIP, Chmod: CHMOD,
	}

	filename := os.Args[1]
	readFile, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "err: %v\n", err)
		os.Exit(ErrReadFromFile)
	}
	defer readFile.Close()

	fileScanner := bufio.NewScanner(readFile)
	fileLines := []string{}
	for fileScanner.Scan() {
		line := strings.TrimSpace(fileScanner.Text())
		if line != "" && !strings.HasPrefix(line, "//") && !strings.HasPrefix(line, "#") {
			fileLines = append(fileLines, line)
		}
	}

	commands, err := tokensStruct.Tokenizer(fileLines)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tokenizer err: %v\n", err)
		os.Exit(ErrTokenizerErr)
	}

	if err := tokensStruct.execTokCmdList(commands); err != nil {
		fmt.Fprintf(os.Stderr, "execution err: %v\n", err)
		os.Exit(ErrExecutionErr)
	}

	fmt.Println("\n[✓] Script execution completed successfully!")
}

func canFuckignRun(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: fuckoff [filename%s]", FileSuffix)
	}
	if !strings.HasSuffix(args[1], FileSuffix) {
		return fmt.Errorf("file must have '%s' suffix", FileSuffix)
	}
	return nil
}

func (t *TokStruct) Tokenizer(lines []string) ([]map[Token][]string, error) {
	var commands []map[Token][]string

	for i, line := range lines {
		lineTok := strings.Fields(line)
		if len(lineTok) == 0 {
			continue
		}

		lineTokLow := strings.ToLower(lineTok[0])

		if len(lineTok) < 2 && lineTokLow != string(PS) && lineTokLow != string(SYSINFO) {
			return nil, fmt.Errorf("line %d: token %s requires arguments", i+1, lineTok[0])
		}

		if tok, ok := isToken(lineTokLow); !ok {
			return nil, fmt.Errorf("line %d: invalid token '%s'", i+1, lineTok[0])
		} else {
			args := []string{}
			if len(lineTok) > 1 {
				args = lineTok[1:]
			}

			if err := t.tokValidator(tok, args); err != nil {
				return nil, fmt.Errorf("line %d: %v", i+1, err)
			}

			command := make(map[Token][]string)
			command[tok] = args
			commands = append(commands, command)
		}
	}
	return commands, nil
}

func isToken(word string) (Token, bool) {
	for _, tok := range ValidTokens {
		if word == string(tok) {
			return tok, true
		}
	}
	return "", false
}

func (t *TokStruct) execTokCmdList(commands []map[Token][]string) error {
	for cmdIndex, command := range commands {
		for tok, args := range command {
			fmt.Printf("[%d] → %s %v\n", cmdIndex+1, tok, args)

			if err := t.runTokCmd(tok, args); err != nil {
				return fmt.Errorf("command %d failed: %v", cmdIndex+1, err)
			}
		}
	}
	return nil
}

func (t *TokStruct) runTokCmd(token Token, args []string) error {
	for i, arg := range args {
		if after, ok := strings.CutPrefix(arg, "$"); ok {
			varName := after
			if val, ok := variables[varName]; ok {
				args[i] = val
			}
		}
	}

	switch token {
	case t.Write:
		return t.executeWrite(args)
	case t.Read:
		return t.executeRead(args)
	case t.Delete:
		return t.executeDelete(args)
	case t.Copy:
		return t.executeCopy(args)
	case t.Move:
		return t.executeMove(args)

	case t.Print:
		return t.executePrint(args)
	case t.Log:
		return t.executeLog(args)

	case t.Exec:
		return t.executeExec(args)
	case t.Sleep:
		return t.executeSleep(args)
	case t.Loop:
		return t.executeLoop(args)

	case t.Ping:
		return t.executePing(args)
	case t.Scan:
		return t.executeScan(args)
	case t.Http:
		return t.executeHttp(args)
	case t.Download:
		return t.executeDownload(args)

	case t.Hash:
		return t.executeHash(args)
	case t.Encode:
		return t.executeEncode(args)
	case t.Decode:
		return t.executeDecode(args)

	case t.Set:
		return t.executeSet(args)
	case t.If:
		return t.executeIf(args)

	case t.Kill:
		return t.executeKill(args)
	case t.Ps:
		return t.executePs()
	case t.Sysinfo:
		return t.executeSysinfo(args)

	case t.Find:
		return t.executeFind(args)
	case t.Grep:
		return t.executeGrep(args)
	case t.Size:
		return t.executeSize(args)

	case t.Nslookup:
		return t.executeNslookup(args)
	case t.Whois:
		return t.executeWhois(args)

	case t.Zip:
		return t.executeZip(args)
	case t.Unzip:
		return t.executeUnzip(args)
	case t.Chmod:
		return t.executeChmod(args)

	default:
		return fmt.Errorf("unknown token: %s", token)
	}
}

func (t *TokStruct) executeWrite(args []string) error {
	text := strings.Join(args[:len(args)-1], " ")
	filename := args[len(args)-1]
	text = strings.Trim(text, `"`)

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(text + "\n")
	if err == nil {
		fmt.Printf("✓ Written to %s\n", filename)
	}
	return err
}

func (t *TokStruct) executeRead(args []string) error {
	content, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("📄 Content of %s:\n%s\n", args[0], string(content))
	return nil
}

func (t *TokStruct) executeDelete(args []string) error {
	err := os.Remove(args[0])
	if err == nil {
		fmt.Printf("🗑️  Deleted %s\n", args[0])
	}
	return err
}

func (t *TokStruct) executeCopy(args []string) error {
	src, dst := args[0], args[1]
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	err = os.WriteFile(dst, input, 0644)
	if err == nil {
		fmt.Printf("📋 Copied %s to %s\n", src, dst)
	}
	return err
}

func (t *TokStruct) executeMove(args []string) error {
	err := os.Rename(args[0], args[1])
	if err == nil {
		fmt.Printf("📦 Moved %s to %s\n", args[0], args[1])
	}
	return err
}

func (t *TokStruct) executePrint(args []string) error {
	text := strings.Join(args, " ")
	text = strings.Trim(text, `"`)
	fmt.Println("💬", text)
	return nil
}

func (t *TokStruct) executeLog(args []string) error {
	text := strings.Join(args, " ")
	text = strings.Trim(text, `"`)
	logEntry := fmt.Sprintf("[%s] %s", time.Now().Format("2006-01-02 15:04:05"), text)

	file, err := os.OpenFile("script.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(logEntry + "\n")
	if err == nil {
		fmt.Printf("📝 Logged: %s\n", text)
	}
	return err
}

func (t *TokStruct) executeExec(args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	fmt.Printf("⚙️  Output: %s\n", string(output))
	return err
}

func (t *TokStruct) executeSleep(args []string) error {
	seconds, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("😴 Sleeping %d seconds...\n", seconds)
	time.Sleep(time.Duration(seconds) * time.Second)
	return nil
}

func (t *TokStruct) executeLoop(args []string) error {
	count, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	}
	command := strings.Join(args[1:], " ")

	for i := range count {
		fmt.Printf("Loop %d/%d: %s\n", i+1, count, command)
		cmd := exec.Command("sh", "-c", command)
		output, _ := cmd.CombinedOutput()
		fmt.Printf("   %s", string(output))
	}
	return nil
}

func (t *TokStruct) executePing(args []string) error {
	host := args[0]
	timeout := time.Second * 3

	conn, err := net.DialTimeout("ip4:icmp", host, timeout)
	if err != nil {
		fmt.Printf("%s is unreachable: %v\n", host, err)
		return err
	}
	defer conn.Close()

	fmt.Printf("%s is reachable\n", host)
	return nil
}

func (t *TokStruct) executeScan(args []string) error {
	host := args[0]
	startPort, _ := strconv.Atoi(args[1])
	endPort, _ := strconv.Atoi(args[2])

	fmt.Printf("Scanning %s ports %d-%d\n", host, startPort, endPort)

	for port := startPort; port <= endPort; port++ {
		address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			fmt.Printf("Port %d OPEN\n", port)
			conn.Close()
		}
	}
	return nil
}

func (t *TokStruct) executeHttp(args []string) error {
	method := strings.ToUpper(args[0])
	url := args[1]

	var resp *http.Response
	var err error

	switch method {
	case "GET":
		resp, err = http.Get(url)
	case "POST":
		resp, err = http.Post(url, "application/json", nil)
	default:
		return fmt.Errorf("unsupported HTTP method: %s", method)
	}

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("HTTP %s %s -> Status: %d\n", method, url, resp.StatusCode)
	fmt.Printf("Response: %s\n", string(body)[:min(200, len(body))])
	return nil
}

func (t *TokStruct) executeDownload(args []string) error {
	url := args[0]
	filename := args[1]

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err == nil {
		fmt.Printf("⬇️ Downloaded %s to %s\n", url, filename)
	}
	return err
}

func (t *TokStruct) executeHash(args []string) error {
	algorithm := strings.ToLower(args[0])
	text := args[1]

	var hash string
	switch algorithm {
	case "md5":
		h := md5.Sum([]byte(text))
		hash = hex.EncodeToString(h[:])
	case "sha256":
		h := sha256.Sum256([]byte(text))
		hash = hex.EncodeToString(h[:])
	default:
		return fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	fmt.Printf("%s hash: %s\n", strings.ToUpper(algorithm), hash)
	return nil
}

func (t *TokStruct) executeEncode(args []string) error {
	encoding := strings.ToLower(args[0])
	text := args[1]

	var encoded string
	switch encoding {
	case "base64":
		encoded = base64.StdEncoding.EncodeToString([]byte(text))
	case "hex":
		encoded = hex.EncodeToString([]byte(text))
	default:
		return fmt.Errorf("unsupported encoding: %s", encoding)
	}

	fmt.Printf("%s encoded: %s\n", strings.ToUpper(encoding), encoded)
	return nil
}

func (t *TokStruct) executeDecode(args []string) error {
	encoding := strings.ToLower(args[0])
	text := args[1]

	var decoded []byte
	var err error

	switch encoding {
	case "base64":
		decoded, err = base64.StdEncoding.DecodeString(text)
	case "hex":
		decoded, err = hex.DecodeString(text)
	default:
		return fmt.Errorf("unsupported encoding: %s", encoding)
	}

	if err != nil {
		return err
	}

	fmt.Printf("🔡 %s decoded: %s\n", strings.ToUpper(encoding), string(decoded))
	return nil
}

func (t *TokStruct) executeSet(args []string) error {
	varName := args[0]
	value := strings.Join(args[1:], " ")
	value = strings.Trim(value, `"`)

	variables[varName] = value
	fmt.Printf("Set $%s = %s\n", varName, value)
	return nil
}

func (t *TokStruct) executeIf(args []string) error {
	left := args[0]
	operator := args[1]
	right := args[2]
	command := strings.Join(args[3:], " ")

	var condition bool
	switch operator {
	case "==":
		condition = left == right
	case "!=":
		condition = left != right
	case "contains":
		condition = strings.Contains(left, right)
	default:
		return fmt.Errorf("unsupported operator: %s", operator)
	}

	if condition {
		fmt.Printf("Condition true, executing: %s\n", command)
		cmd := exec.Command("sh", "-c", command)
		output, _ := cmd.CombinedOutput()
		fmt.Printf("   %s", string(output))
	} else {
		fmt.Printf("Condition false, skipping\n")
	}
	return nil
}

func (t *TokStruct) executeKill(args []string) error {
	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	err = process.Kill()
	if err == nil {
		fmt.Printf("Killed process %d\n", pid)
	}
	return err
}

func (t *TokStruct) executePs() error {
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	fmt.Printf("👥 Processes:\n%s\n", string(output))
	return nil
}

func (t *TokStruct) executeSysinfo(args []string) error {
	hostname, _ := os.Hostname()
	wd, _ := os.Getwd()

	fmt.Printf("   System Info:\n")
	fmt.Printf("   Hostname: %s\n", hostname)
	fmt.Printf("   Working Dir: %s\n", wd)
	fmt.Printf("   User: %s\n", os.Getenv("USER"))
	fmt.Printf("   OS: %s\n", os.Getenv("GOOS"))
	return nil
}

func (t *TokStruct) executeFind(args []string) error {
	pattern := args[0]
	dir := "."
	if len(args) > 1 {
		dir = args[1]
	}

	fmt.Printf("Searching for '%s' in %s\n", pattern, dir)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if matched, _ := filepath.Match(pattern, info.Name()); matched {
			fmt.Printf("   %s\n", path)
		}
		return nil
	})
	return err
}

func (t *TokStruct) executeGrep(args []string) error {
	pattern := args[0]
	filename := args[1]

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	fmt.Printf("Grepping '%s' in %s\n", pattern, filename)

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if regex.MatchString(line) {
			fmt.Printf("   %d: %s\n", lineNum, line)
		}
	}
	return scanner.Err()
}

func (t *TokStruct) executeSize(args []string) error {
	filename := args[0]
	info, err := os.Stat(filename)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %d bytes\n", filename, info.Size())
	return nil
}

func (t *TokStruct) executeNslookup(args []string) error {
	host := args[0]
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}

	fmt.Printf("DNS lookup for %s:\n", host)
	for _, ip := range ips {
		fmt.Printf("   %s\n", ip.String())
	}
	return nil
}

func (t *TokStruct) executeWhois(args []string) error {
	domain := args[0]
	fmt.Printf("WHOIS lookup for %s\n", domain)

	cmd := exec.Command("whois", domain)
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines[:min(20, len(lines))] {
		if strings.TrimSpace(line) != "" {
			fmt.Printf("   %s\n", line)
		}
	}
	return nil
}

func (t *TokStruct) executeZip(args []string) error {
	zipFile := args[0]
	files := args[1:]

	fmt.Printf("Creating zip %s with files: %v\n", zipFile, files)

	cmd := exec.Command("zip", append([]string{zipFile}, files...)...)
	err := cmd.Run()
	if err == nil {
		fmt.Printf("Created %s\n", zipFile)
	}
	return err
}

func (t *TokStruct) executeUnzip(args []string) error {
	zipFile := args[0]
	dest := "."
	if len(args) > 1 {
		dest = args[1]
	}

	fmt.Printf("Extracting %s to %s\n", zipFile, dest)

	cmd := exec.Command("unzip", zipFile, "-d", dest)
	err := cmd.Run()
	if err == nil {
		fmt.Printf("Extracted %s\n", zipFile)
	}
	return err
}

func (t *TokStruct) executeChmod(args []string) error {
	perm := args[0]
	file := args[1]

	cmd := exec.Command("chmod", perm, file)
	err := cmd.Run()
	if err == nil {
		fmt.Printf("Changed permissions of %s to %s\n", file, perm)
	}
	return err
}

func (t *TokStruct) tokValidator(token Token, args []string) error {
	switch token {
	case t.Write:
		if len(args) < 2 {
			return fmt.Errorf("write requires text and filename")
		}
	case t.Scan:
		if len(args) != 3 {
			return fmt.Errorf("scan requires host, start_port, end_port")
		}
	case t.Hash:
		if len(args) != 2 {
			return fmt.Errorf("hash requires algorithm and text")
		}
	case t.Set:
		if len(args) < 2 {
			return fmt.Errorf("set requires variable name and value")
		}
	case t.If:
		if len(args) < 4 {
			return fmt.Errorf("if requires: value operator value command")
		}
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
