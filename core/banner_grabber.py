import socket
import ssl
import subprocess
import platform
import re

"""
PROBES tanımlamamızın sebebi bazı servisler bağlandığımız gibi banner(tanıtımlarını) bize gönderir.
Ve hangi sürümü vesaaire kullandıklarını söyler (FTP, SSH vs.) ama bazı servisler bizden istek bekler.
Eğer o istek gelmezse banner göndermezler. Bu yüzden bazı portlar için probe gönderiyoruz.
"""

PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",  
    21: b"",   
    22: b"",   
    25: b"",   
    110: b"",  
    143: b"",  
    6379: b"PING\r\n",     
    11211: b"version\r\n",      
    5900: b"",                   
    23: b"",                     
    3306: b"",                  
}

DEFAULT_PROBE = b"\r\n"  # Bilinmeyen portlar için nötr bir prob


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """
   Burada ise socket kütüphanesi ile hedefe tcp bağlantısı kurup banner'ı almaya çalışıyoruz.
     Eğer port 443 veya 8443 ise SSL handshake yapıyoruz.
    """

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        if port in (443, 8443):
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                sock = context.wrap_socket(sock, server_hostname=ip)
            except ssl.SSLError:
                # SSL handshake başarısız olursa normal soket ile devam et
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
