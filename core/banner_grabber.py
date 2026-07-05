"""
banner_grabber.py
Açık bir porta bağlanıp servisin kendini tanıttığı ilk veriyi (banner) okur.
Bazı servisler (HTTP gibi) bağlantı kurulduğunda kendiliğinden veri göndermez,
bu yüzden protokole özel küçük "prob" istekleri gönderiyoruz.
nmap'in service-probes veritabanının çok küçük bir alt kümesi gibi düşünülebilir.
"""

import socket
import ssl
import subprocess
import platform
import re

# Bazı iyi bilinen portlar için gönderilecek prob istekleri.
# Anahtar: port numarası, değer: gönderilecek bytes
PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",  # TLS handshake sonrasi kullanilacak
    21: b"",   # FTP zaten bağlanınca banner yollar
    22: b"",   # SSH zaten bağlanınca banner yollar
    25: b"",   # SMTP zaten bağlanınca banner yollar
    110: b"",  # POP3 zaten banner yollar
    143: b"",  # IMAP zaten banner yollar
    6379: b"PING\r\n",           # Redis
    11211: b"version\r\n",       # Memcached
    5900: b"",                   # VNC zaten banner yollar (RFB ...)
    23: b"",                     # Telnet genelde login prompt yollar
    3306: b"",                   # MySQL handshake paketini kendisi yollar
}

DEFAULT_PROBE = b"\r\n"  # Bilinmeyen portlar için nötr bir prob


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Belirtilen ip:port adresine bağlanır, banner okumaya çalışır.
    Gerekirse SSL/TLS handshake yapar.
    Başarısız olursa boş string döner.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Eğer bilinen SSL portları ise (örn: 443, 8443) güvenli bağlantı kurmayı dene
        if port in (443, 8443):
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                sock = context.wrap_socket(sock, server_hostname=ip)
            except ssl.SSLError:
                # SSL handshake başarısız olursa normal soket ile devam et (bazen bu portlarda düz HTTP çalışır)
                pass

        probe = PROBES.get(port, DEFAULT_PROBE)
        if probe:
            try:
                sock.sendall(probe)
            except OSError:
                pass

        try:
            data = sock.recv(1024)
        except socket.timeout:
            data = b""
        finally:
            sock.close()

        return data.decode(errors="ignore")
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""


def get_ttl_hint(ip: str, port: int = None, timeout: float = 2.0):
    """
    İşletim sisteminin kendi PING aracını kullanarak hedeften dönen TTL'i okur.
    Gerçek işletim sistemi tahminini sadece bu şekilde yapabiliriz.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
    
    # timeout değerini tam sayıya çevir (bazı ping versiyonları float sevmez)
    timeout_int = max(1, int(timeout))

    command = ["ping", param, "1", timeout_param, str(timeout_int), ip]

    try:
        # Ping komutunu çalıştır
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        # Windows ve Linux çıktı formatında "TTL=" veya "ttl=" arıyoruz
        match = re.search(r"(?i)ttl=(\d+)", output)
        if match:
            return int(match.group(1))
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return None
