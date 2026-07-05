"""
TCP connect scan yapan çekirdek modül.
ThreadPoolExecutor kullanarak birden çok portu paralel tarar.

Not: Bu, nmap'in -sT özelliğinin basit versiyonudur.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def _scan_single_port(ip: str, port: int, timeout: float):
    """Tek bir portu tarar. Açıksa True, kapalıysa False döner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return port, result == 0
    except socket.gaierror:
        raise
    except OSError:
        return port, False


def scan_ports(ip: str, ports, timeout: float = 1.0, max_threads: int = 100, progress_callback=None):
    """
    Verilen port listesini paralel olarak tarar.

    Args:
        ip: Hedef IP adresi veya hostname
        ports: taranacak port numaralarının iterable'ı
        timeout: her bağlantı denemesi için saniye cinsinden zaman aşımı
        max_threads: aynı anda çalışacak maksimum thread sayısı
        progress_callback: her port tarandığında çağrılan fonksiyon (opsiyonel)

    Returns:
        Açık portların sıralı listesi (list[int])
    """
    open_ports = []
    total = len(ports)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(_scan_single_port, ip, port, timeout): port for port in ports}

        for future in as_completed(futures):
            port, is_open = future.result()
            completed += 1
            if progress_callback:
                progress_callback(completed, total, port, is_open)
            if is_open:
                open_ports.append(port)

    return sorted(open_ports)


def parse_port_range(port_str: str):
    """
    '1-1000' veya '22,80,443' veya '22,80,1000-2000' gibi ifadeleri
    port numaralarının bir listesine çevirir.
    """
    ports = set()
    parts = port_str.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)
