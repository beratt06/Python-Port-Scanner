"""
syn_scanner.py
Gerçek bir "TCP SYN scan" (nmap'in -sS modu) implementasyonu.

Nasıl çalışır:
1. Hedefe elle inşa edilmiş bir TCP SYN paketi gönderilir (tam bağlantı
   KURULMAZ, sadece ilk paket).
2. Hedef açık bir portsa SYN-ACK ile cevap verir; kapalıysa RST ile cevap
   verir; bir firewall paketi sessizce düşürüyorsa hiç cevap gelmez
   (bu durum "filtered" olarak işaretlenir).
3. Bizim TCP/IP yığınımız bu SYN-ACK'i tanımadığı için (bizim başlattığımız
   soket bilgisi çekirdekte yok, çünkü paketi elle oluşturduk) otomatik
   olarak bir RST göndererek yarım kalan bağlantıyı temizler. Bu, klasik
   SYN scan'in "gizli/yarı-açık" (half-open) olarak adlandırılmasının sebebidir.

GEREKSİNİM: Bu modül raw socket kullanır, bu yüzden ROOT / Administrator
yetkisi (Linux'ta CAP_NET_RAW) gerektirir. Yetkisiz çalıştırılırsa
PermissionError fırlatılır ve scanner.py bunu yakalayıp normal TCP
connect scan'e otomatik döner.
"""

import os
import socket
import struct
import threading
import time
import random


def _checksum(data: bytes) -> int:
    """Standart internet checksum (IP ve TCP header'ları için)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _build_ip_header(src_ip: str, dst_ip: str, payload_len: int, ip_id: int) -> bytes:
    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 20 + payload_len
    flags_fragment_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_TCP
    header_checksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_length, ip_id, flags_fragment_offset,
        ttl, protocol, header_checksum, src_bytes, dst_bytes,
    )
    header_checksum = _checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_length, ip_id, flags_fragment_offset,
        ttl, protocol, header_checksum, src_bytes, dst_bytes,
    )
    return header


def _build_tcp_syn(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int) -> bytes:
    ack_seq = 0
    data_offset = (5 << 4) + 0  # 5 * 4 = 20 byte header, ek seçenek yok
    flags = 0x02  # SYN bayrağı
    window = socket.htons(5840)
    urg_ptr = 0

    # Önce checksum alanı 0 olarak paket oluşturulur
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack_seq, data_offset, flags, window, 0, urg_ptr,
    )

    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, socket.IPPROTO_TCP, len(tcp_header),
    )
    checksum = _checksum(pseudo_header + tcp_header)

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack_seq, data_offset, flags, window, checksum, urg_ptr,
    )
    return tcp_header


def _get_local_ip(dst_ip: str) -> str:
    """Hedefe paket göndermek için kullanılacak yerel arayüz IP'sini bulur."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows gibi geteuid'in olmadığı platformlarda kontrol edilemez,
        # deneme sırasında PermissionError alınırsa zaten fallback yapılacak.
        return True


def syn_scan(target_ip: str, ports, timeout: float = 2.5, src_port: int = None, progress_callback=None):
    """
    Verilen portlar için SYN scan yapar.

    Returns:
        dict: {port: "open" | "closed" | "filtered"}

    Raises:
        PermissionError: root/administrator yetkisi yoksa
    """
    if not is_root():
        raise PermissionError("SYN scan için root/administrator yetkisi gereklidir.")

    src_ip = _get_local_ip(target_ip)
    src_port = src_port or random.randint(40000, 60000)

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.settimeout(0.5)
    except OSError as e:
        # Windows'ta raw socket açmak özel yetkiler ve koşullar gerektirdiğinden genelde WSAEACCES vb hatalar fırlatılır.
        raise PermissionError(f"Ham soket oluşturulamadı (OS Hatası: {e}). SYN scan için yetki veya uygun ortam yok.")

    results = {}
    lock = threading.Lock()
    stop_event = threading.Event()

    def sniffer():
        while not stop_event.is_set():
            try:
                packet, _addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            if len(packet) < 40:
                continue

            ip_header = packet[0:20]
            ihl = (ip_header[0] & 0x0F) * 4
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            src_addr = socket.inet_ntoa(iph[8])

            if src_addr != target_ip:
                continue

            tcp_header = packet[ihl:ihl + 20]
            if len(tcp_header) < 20:
                continue
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            resp_src_port = tcph[0]
            resp_dst_port = tcph[1]
            flags = tcph[5]

            if resp_dst_port != src_port:
                continue

            with lock:
                if resp_src_port not in results:
                    if flags & 0x12 == 0x12:      # SYN+ACK -> açık
                        results[resp_src_port] = "open"
                    elif flags & 0x04:             # RST -> kapalı
                        results[resp_src_port] = "closed"

    sniff_thread = threading.Thread(target=sniffer, daemon=True)
    sniff_thread.start()

    total = len(ports)
    try:
        for i, port in enumerate(ports):
            ip_id = random.randint(1, 65535)
            seq = random.randint(0, 2**32 - 1)
            tcp_segment = _build_tcp_syn(src_ip, target_ip, src_port, port, seq)
            ip_segment = _build_ip_header(src_ip, target_ip, len(tcp_segment), ip_id)
            packet = ip_segment + tcp_segment
            send_sock.sendto(packet, (target_ip, 0))
            if progress_callback:
                progress_callback(i + 1, total, port, None)

        # Cevapların gelmesi için bekle
        time.sleep(timeout)
    finally:
        stop_event.set()
        sniff_thread.join(timeout=1)
        send_sock.close()
        recv_sock.close()

    # Cevap gelmeyen portlar "filtered" (muhtemel firewall / paket kaybı)
    final_results = {}
    for port in ports:
        final_results[port] = results.get(port, "filtered")

    return final_results
