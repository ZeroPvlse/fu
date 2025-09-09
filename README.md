# FU - Cybersecurity Scripting Language

**FU** (short for "Fuck You") is a simple yet powerful scripting language designed specifically for cybersecurity professionals, ethical hackers, and security researchers. It provides all the essential tools you need for penetration testing, automation, and security analysis without the complexity of learning Python or other full programming languages.

## Why FU?

- **Simple Syntax** - No complex programming concepts, just commands and arguments
- **Security-focused** - Built-in tools for networking, crypto, file analysis, and system operations
- **Fast Execution** - Lightweight interpreter for quick automation tasks
- **Ethical Hacking Ready** - Perfect for CTFs, penetration testing, and security research

## Quick Start

### Installation

1. Build the interpreter:
```bash
go build -o fuckoff main.go
```

2. Create your first script (`hello.fu`):
```
print "Hello, mr hacker!"
sysinfo
```

3. Run it:
```bash
./fuckoff hello.fu
```

## Language Reference

### File Operations

| Command | Syntax | Description |
|---------|--------|-------------|
| `read` | `read filename` | Read and display file contents |
| `write` | `write "text" filename` | Write text to file (append mode) |
| `delete` | `delete filename` | Delete a file |
| `copy` | `copy source dest` | Copy file from source to destination |
| `move` | `move source dest` | Move/rename file |
| `size` | `size filename` | Display file size in bytes |

**Examples:**
```
write "Secret data" secrets.txt
read secrets.txt
copy secrets.txt backup.txt
size backup.txt
delete secrets.txt
```

### Network Operations

| Command | Syntax | Description |
|---------|--------|-------------|
| `ping` | `ping host` | Check if host is reachable |
| `scan` | `scan host start_port end_port` | TCP port scanner |
| `http` | `http METHOD url` | Send HTTP requests (GET/POST) |
| `download` | `download url filename` | Download file from URL |
| `nslookup` | `nslookup domain` | DNS lookup |
| `whois` | `whois domain` | WHOIS domain information |

**Examples:**
```
ping google.com
scan 192.168.1.1 80 443
http GET https://httpbin.org/get
download https://example.com/file.txt downloaded.txt
nslookup github.com
whois example.com
```

### Cryptography & Encoding

| Command | Syntax | Description |
|---------|--------|-------------|
| `hash` | `hash algorithm text` | Generate hash (md5, sha256) |
| `encode` | `encode format text` | Encode data (base64, hex) |
| `decode` | `decode format encoded_text` | Decode data |

**Examples:**
```
hash md5 "password123"
hash sha256 "sensitive_data"
encode base64 "secret message"
decode base64 "c2VjcmV0IG1lc3NhZ2U="
encode hex "hello world"
```

### Variables & Logic

| Command | Syntax | Description |
|---------|--------|-------------|
| `set` | `set varname "value"` | Create/set variable |
| `if` | `if value operator value command` | Conditional execution |

**Operators:** `==`, `!=`, `contains`

**Examples:**
```
set target "192.168.1.1"
set port "22"
scan $target $port $port

set password "admin123"
if $password == "admin123" print "Weak password detected!"
if $target contains "192.168" print "Private IP range"
```

### System Operations

| Command | Syntax | Description |
|---------|--------|-------------|
| `exec` | `exec command args` | Execute system command |
| `ps` | `ps` | List running processes |
| `kill` | `kill pid` | Kill process by PID |
| `sysinfo` | `sysinfo` | Display system information |
| `chmod` | `chmod permissions filename` | Change file permissions |
| `sleep` | `sleep seconds` | Pause execution |
| `loop` | `loop count command` | Repeat command N times |

**Examples:**
```
exec ls -la
ps
sysinfo
chmod 755 script.sh
sleep 5
loop 3 echo "Brute force attempt"
```

### File Analysis

| Command | Syntax | Description |
|---------|--------|-------------|
| `find` | `find pattern [directory]` | Find files by pattern |
| `grep` | `grep pattern filename` | Search text in files |

**Examples:**
```
find "*.log" /var/log
find "passwd*" /etc
grep "error" application.log
grep "admin" users.txt
```

### Archive Operations

| Command | Syntax | Description |
|---------|--------|-------------|
| `zip` | `zip archive.zip file1 file2 ...` | Create ZIP archive |
| `unzip` | `unzip archive.zip [destination]` | Extract ZIP archive |

**Examples:**
```
zip evidence.zip logs.txt config.ini
unzip evidence.zip /tmp/analysis
```

### Output & Logging

| Command | Syntax | Description |
|---------|--------|-------------|
| `print` | `print "message"` | Print to console |
| `log` | `log "message"` | Log with timestamp to script.log |

**Examples:**
```
print "Starting security scan"
log "Scan initiated by user"
log "Suspicious activity detected"
```

## Real-World Example Scripts

### 1. Network Reconnaissance (`recon.fu`)

```
print "Starting reconnaissance"
set target "example.com"

log "Starting recon on $target"
print "Gathering DNS information..."
nslookup $target

print "Getting WHOIS data..."
whois $target

print "Scanning common ports..."
scan $target 21 25
scan $target 53 80
scan $target 443 443

print "Testing HTTP response..."
http GET https://$target

log "Reconnaissance completed for $target"
print "Recon complete! Check script.log for details"
```

### 2. Log Analysis (`loganalyzer.fu`)

```
print "Starting log analysis"
set logfile "/var/log/auth.log"

print "Analyzing authentication logs..."
grep "Failed password" $logfile
grep "Invalid user" $logfile
grep "Accepted password" $logfile

print "Looking for suspicious IPs..."
grep "sshd" $logfile

size $logfile
log "Log analysis completed"
```

### 3. File Integrity Checker (`integrity.fu`)

```
print "File Integrity Checker"
set important_file "/etc/passwd"

print "Checking file: $important_file"
size $important_file

print "Generating checksums..."
read $important_file
hash md5 "$important_file"
hash sha256 "$important_file"

print "Creating backup..."
copy $important_file passwd_backup.txt

log "Integrity check completed for $important_file"
```

### 4. Automated Pentesting (`pentest.fu`)

```
print "Automated Penetration Test"
set target "192.168.1.0/24"

log "Starting pentest on $target network"

print "Phase 1: Host Discovery"
loop 10 ping 192.168.1.$i

print "Phase 2: Port Scanning"
scan 192.168.1.1 1 1000
scan 192.168.1.100 80 443

print "Phase 3: Service Enumeration"
http GET http://192.168.1.1
nslookup 192.168.1.1

print "Phase 4: Data Collection"
write "Target: 192.168.1.1" pentest_results.txt
write "Open ports found" pentest_results.txt

log "Pentest completed - results saved"
print "Pentest complete! Check pentest_results.txt"
```

### 5. Incident Response (`incident.fu`)

```
print "Incident Response Script"

log "INCIDENT: Starting emergency response"

print "Gathering system information..."
sysinfo
ps

print "Checking for suspicious files..."
find "*.tmp" /tmp
find "suspicious*" /home

print "Analyzing network connections..."
exec netstat -tuln
exec ss -tuln

print "Creating evidence archive..."
zip evidence.zip script.log
zip evidence.zip /var/log/auth.log

print "Securing evidence..."
chmod 600 evidence.zip

log "Evidence collected and secured"
print "Incident response complete - evidence preserved"
```

### 6. Password Security Audit (`passaudit.fu`)

```
print "Password Security Audit"

set wordlist "rockyou.txt"
set target_hash "5d41402abc4b2a76b9719d911017c592"

print "Analyzing password strength..."
hash md5 "hello"
hash md5 "password"
hash md5 "123456"

if $target_hash == "5d41402abc4b2a76b9719d911017c592" print "⚠️ WEAK PASSWORD DETECTED!"

print "Checking common passwords..."
grep "password" $wordlist
grep "admin" $wordlist

log "Password audit completed"
write "Audit results: Weak passwords found" audit_report.txt
```

## Advanced Usage

### Comment Support
Use `//` or `#` for comments:
```
// This is a comment
print "Hello World"  // Another comment
# This is also a comment
```

### Variable Usage
Variables can be used anywhere in commands:
```
set domain "example.com"
set port "80"
scan $domain $port $port
http GET https://$domain
```

### Error Handling
The interpreter provides detailed error messages with line numbers:
```
Line 5: invalid token 'invalid_command'
Line 12: scan requires host, start_port, end_port
```

## Best Practices

1. **Always log important actions** - Use `log` for audit trails
2. **Use variables for reusability** - Set targets, ports, and paths as variables
3. **Comment your scripts** - Document what each section does
4. **Test in safe environments** - Never run untested scripts on production systems
5. **Backup important data** - Use `copy` before modifying files
6. **Follow responsible disclosure** - Only use on systems you own or have permission to test

## Security Considerations

- **Legal Use Only** - Only use FU on systems you own or have explicit permission to test
- **Be Responsible** - This tool is for legitimate security testing and research
- **Protect Credentials** - Never hardcode passwords or sensitive data in scripts
- **Audit Trail** - Always maintain logs of your testing activities
- **Clean Up** - Remove temporary files and evidence after testing

## Error Codes

| Code | Description |
|------|-------------|
| 1 | Invalid arguments |
| 2 | File read error |
| 3 | Tokenizer error |
| 4 | Execution error |

## File Extensions

All FU scripts must use the `.fu` extension:
```bash
./fuckoff myscript.fu
```

## Contributing

Want to add more features? Here's how:

1. Add new tokens to the `Token` constants
2. Update `ValidTokens` slice
3. Add the new command to the `runTokCmd` switch statement
4. Implement the execution function
5. Add validation in `tokValidator`

## License

This project is for educational and legitimate security testing purposes only. Use responsibly and ethically.

---

**Happy Ethical Hacking!** 

*Remember: With great power comes great responsibility. Use FU only for legitimate security testing and research.*
