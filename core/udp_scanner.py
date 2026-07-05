"""
udp_scanner.py
UDP portlarını tarar. UDP bağlantısız bir protokol olduğu için "açık" kavramı
TCP'deki kadar net değildir:

- Cevap (veri) geldi           -> açık (open)
- ICMP "port unreachable" geldi -> kapalı (closed)
- Hiçbir cevap gelmedi (timeout) -> açık|filtrelenmiş (open|filtered) — belirsiz,
  çünkü hem "servis paketi sessizce yok saydı" hem de "bir firewall paketi
  düşürdü" aynı sonucu (sessizlik) verir. nmap da tam olarak bu belirsizliği
  aynı şekilde raporlar.

Bazı servisler boş paket gönderildiğinde cevap vermez; bu yüzden bilinen
UDP servisleri için basit protokole özel prob'lar tanımlanmıştır.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# DNS: "google.com" için standart A kaydı sorgusu (basit, sabit bir DNS query paketi)
_DNS_QUERY = (
    b"\xaa\xaa"          # Transaction ID
    b"\x01\x00"          # Standart sorgu, recursion istekli
    b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 soru, 0 cevap/authority/additional
    b"\x06google\x03com\x00"  # QNAME: google.com
    b"\x00\x01\x00\x01"   # QTYPE=A, QCLASS=IN
)

# NTP: Client mode (mode=3) isteği - 48 byte'lık standart NTP paketi
_NTP_REQUEST = b"\x1b" + 47 * b"\x00"

# NetBIOS Name Service basit sorgu (çok kaba, her zaman çalışmayabilir)
_NBNS_QUERY = (
    b"\xaa\xaa\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
)

UDP_PROBES = {
    53: _DNS_QUERY,
    123: _NTP_REQUEST,
    137: _NBNS_QUERY,
}

DEFAULT_PROBE = b"\x00"  # Nötr / boş prob


def _scan_single_udp_port(ip: str, port: int, timeout: float):
    probe = UDP_PROBES.get(port, DEFAULT_PROBE)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.send(probe)
        try:
            data, _ = sock.recvfrom(2048)
            return port, "open", data
        except socket.timeout:
            return port, "open|filtered", None
        except (ConnectionRefusedError, ConnectionResetError):
            # Linux'ta ICMP "port unreachable" cevabı ConnectionRefusedError olarak yansır.
            # Windows'ta ise ConnectionResetError (10054) hatası olarak döner.
            return port, "closed", None
    except OSError:
        return port, "error", None
    finally:
        sock.close()


def scan_udp_ports(ip: str, ports, timeout: float = 2.0, max_threads: int = 50, progress_callback=None):
    """
    Verilen UDP portlarını paralel tarar.

    Returns:
        dict: {port: {"state": "open"/"closed"/"open|filtered", "raw_banner": bytes|None}}
    """
    results = {}
    total = len(ports)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(_scan_single_udp_port, ip, port, timeout): port for port in ports}

        for future in as_completed(futures):
            port, state, data = future.result()
            completed += 1
            if progress_callback:
                progress_callback(completed, total, port, state)
            results[port] = {
                "state": state,
                "raw_banner": data.decode(errors="ignore") if data else "",
            }

    return results
