#!/usr/bin/env python3
"""
scanner.py
Basitleştirilmiş nmap klonu - Ana giriş noktası.

Kullanım örnekleri:
    python scanner.py -t 192.168.1.10 -p 1-1000
    python scanner.py -t example.com -p 22,80,443 --output rapor.json
    python scanner.py -t 127.0.0.1 -p 1-65535 --threads 200 --format html --output rapor.html
    sudo python scanner.py -t 192.168.1.10 -p 1-1000 --scan-type syn
    python scanner.py -t 192.168.1.10 -p 53,123,161 --scan-type udp

ÖNEMLİ: Bu aracı yalnızca sahibi olduğunuz veya tarama izniniz olan
sistemlerde kullanın. İzinsiz tarama birçok ülkede suç teşkil edebilir.
"""

import argparse
import socket
import sys
import os
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from core.port_scanner import scan_ports, parse_port_range
from core.banner_grabber import grab_banner, get_ttl_hint
from core.fingerprint import identify_service
from core.os_guess import guess_os
from core.syn_scanner import syn_scan, is_root
from core.udp_scanner import scan_udp_ports
from report.exporter import export_json, export_csv, export_html, build_result_dict

# ANSI renk kodları (terminalde renkli çıktı için)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def resolve_target(target: str) -> str:
    """Hostname verilmişse IP adresine çevirir."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{RED}[!] Hedef çözümlenemedi: {target}{RESET}")
        sys.exit(1)


def print_banner():
    print(f"""{CYAN}{BOLD}
    ╔══════════════════════════════════════╗
    ║        MINI NMAP  -  v0.2             ║
    ║   Basit Port Tarayıcı & Banner Grabber║
    ╚══════════════════════════════════════╝
    {RESET}""")


def progress_printer(completed, total, port, extra):
    percent = (completed / total) * 100
    bar_length = 30
    filled = int(bar_length * completed // total)
    bar = "█" * filled + "-" * (bar_length - filled)
    sys.stdout.write(f"\r    [{bar}] {percent:5.1f}%  ({completed}/{total})")
    sys.stdout.flush()
    if completed == total:
        print()  # yeni satır


def run_connect_scan(ip, ports, args):
    """Klasik TCP connect scan (full handshake) + banner grabbing."""
    open_ports = scan_ports(
        ip, ports,
        timeout=args.timeout,
        max_threads=args.threads,
        progress_callback=progress_printer
    )

    open_ports_info = []
    for port in open_ports:
        service_info = {"port": port, "protocol": "tcp", "state": "open",
                         "service": None, "version": None, "raw_banner": "", "risk_note": None}
        if not args.no_banner:
            banner = grab_banner(ip, port, timeout=args.timeout + 1)
            identified = identify_service(banner, port=port, protocol="tcp")
            service_info.update(identified)
            service_info["port"] = port
        open_ports_info.append(service_info)

    return open_ports_info


def run_syn_scan(ip, ports, args):
    """Raw socket tabanlı SYN scan (yarı-açık tarama) + (isteğe bağlı) banner grabbing."""
    if not is_root():
        print(f"{YELLOW}[!] SYN scan root/administrator yetkisi gerektirir. "
              f"'sudo' ile çalıştırın. TCP connect scan'e geri dönülüyor.{RESET}\n")
        return run_connect_scan(ip, ports, args)

    try:
        state_map = syn_scan(ip, ports, timeout=max(args.timeout * 2, 2.0),
                              progress_callback=progress_printer)
    except PermissionError as e:
        print(f"{YELLOW}[!] {e} TCP connect scan'e geri dönülüyor.{RESET}\n")
        return run_connect_scan(ip, ports, args)

    open_ports_info = []
    for port, state in sorted(state_map.items()):
        if state != "open":
            continue
        service_info = {"port": port, "protocol": "tcp", "state": state,
                         "service": None, "version": None, "raw_banner": "", "risk_note": None}
        # SYN scan tam bağlantı kurmadığı için banner almak isteniyorsa
        # ayrıca normal bir TCP bağlantısı ile banner çekilir.
        if not args.no_banner:
            banner = grab_banner(ip, port, timeout=args.timeout + 1)
            identified = identify_service(banner, port=port, protocol="tcp")
            service_info.update(identified)
            service_info["port"] = port
        open_ports_info.append(service_info)

    return open_ports_info


def run_udp_scan(ip, ports, args):
    """UDP port taraması (open / closed / open|filtered)."""
    results = scan_udp_ports(ip, ports, timeout=max(args.timeout, 1.5),
                              max_threads=args.threads, progress_callback=progress_printer)

    open_ports_info = []
    for port, info in sorted(results.items()):
        if info["state"] == "closed":
            continue  # sadece açık / belirsiz olanları raporla
        banner = info.get("raw_banner", "")
        identified = identify_service(banner, port=port, protocol="udp")
        service_info = {
            "port": port, "protocol": "udp", "state": info["state"],
            "service": identified["service"], "version": identified["version"],
            "raw_banner": identified["raw_banner"], "risk_note": identified["risk_note"],
        }
        open_ports_info.append(service_info)

    return open_ports_info


def print_results_table(open_ports_info):
    if not open_ports_info:
        return
    print(f"{BOLD}{'PORT/PROTO':<14}{'DURUM':<16}{'SERVİS':<24}{'VERSİYON':<16}{RESET}")
    print("-" * 70)
    for info in open_ports_info:
        port_str = f"{info['port']}/{info.get('protocol', 'tcp')}"
        state_str = info.get("state", "open")
        service_str = info.get("service") or "-"
        version_str = info.get("version") or "-"

        state_color = GREEN if state_str == "open" else YELLOW
        print(f"{state_color}{port_str:<14}{RESET}{state_str:<16}{service_str:<24}{version_str:<16}")
        if info.get("risk_note"):
            print(f"    {RED}⚠  {info['risk_note']}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Basitleştirilmiş nmap klonu - port tarama ve banner grabbing aracı"
    )
    parser.add_argument("-t", "--target", required=True, help="Hedef IP adresi veya hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Port aralığı/listesi. Örn: 1-1000 veya 22,80,443 (varsayılan: 1-1024)")
    parser.add_argument("--scan-type", choices=["connect", "syn", "udp"], default="connect",
                         help="Tarama türü: connect (varsayılan, tam TCP handshake), "
                              "syn (yarı-açık, root gerekir), udp (UDP portları)")
    parser.add_argument("--threads", type=int, default=100, help="Maksimum paralel thread sayısı (varsayılan: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Bağlantı zaman aşımı, saniye (varsayılan: 1.0)")
    parser.add_argument("--no-banner", action="store_true", help="Banner grabbing yapma, sadece port tara")
    parser.add_argument("--output", help="Sonuçların kaydedileceği dosya yolu")
    parser.add_argument("--format", choices=["json", "csv", "html"], default="json",
                         help="Çıktı formatı (varsayılan: json)")
    parser.add_argument("--os-guess", action="store_true", help="Kaba TTL tabanlı OS tahmini yap")

    args = parser.parse_args()

    print_banner()

    ip = resolve_target(args.target)
    ports = parse_port_range(args.ports)

    scan_type_labels = {"connect": "TCP Connect Scan", "syn": "TCP SYN Scan (yarı-açık)", "udp": "UDP Scan"}
    print(f"    Hedef        : {args.target} ({ip})")
    print(f"    Tarama türü  : {scan_type_labels[args.scan_type]}")
    print(f"    Port sayısı  : {len(ports)}")
    print(f"    Thread       : {args.threads}")
    print(f"    Zaman aşımı  : {args.timeout}s\n")

    start_time = time.time()
    print(f"{YELLOW}[*] Tarama başlıyor...{RESET}")

    if args.scan_type == "connect":
        open_ports_info = run_connect_scan(ip, ports, args)
    elif args.scan_type == "syn":
        open_ports_info = run_syn_scan(ip, ports, args)
    else:  # udp
        open_ports_info = run_udp_scan(ip, ports, args)

    elapsed = time.time() - start_time
    print(f"\n{GREEN}[+] Tarama tamamlandı. Süre: {elapsed:.2f} saniye{RESET}")
    print(f"{GREEN}[+] {len(open_ports_info)} port raporlandı.{RESET}\n")

    print_results_table(open_ports_info)

    os_guess_result = None
    if args.os_guess and open_ports_info:
        first_tcp_port = next((p["port"] for p in open_ports_info if p.get("protocol") == "tcp"), None)
        if first_tcp_port:
            ttl = get_ttl_hint(ip, first_tcp_port, timeout=args.timeout + 1)
            os_guess_result = guess_os(ttl)
            print(f"\n{CYAN}[i] Tahmini işletim sistemi: {os_guess_result}{RESET}")

    results = build_result_dict(
        target=f"{args.target} ({ip})",
        open_ports_info=open_ports_info,
        total_ports_scanned=len(ports),
        os_guess=os_guess_result,
    )
    results["scan_type"] = args.scan_type

    if args.output:
        if args.format == "json":
            export_json(results, args.output)
        elif args.format == "csv":
            export_csv(results, args.output)
        elif args.format == "html":
            export_html(results, args.output)
        print(f"\n{GREEN}[+] Rapor kaydedildi: {args.output} ({args.format}){RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Tarama kullanıcı tarafından durduruldu.{RESET}")
        os._exit(1)
