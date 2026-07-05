"""
Banner metnine bakarak servis adı ve versiyonunu tahmin eden basit,
regex tabanlı bir imza veritabanı.

nmap'in -sV özelliğinin basit versiyonu
"""

import re

from core.common_ports import guess_service_by_port

SIGNATURES = [
    # --- SSH ---
    (re.compile(r"SSH-([\d.]+)-OpenSSH[_-]([\w.]+)", re.I), "OpenSSH", 2),
    (re.compile(r"SSH-([\d.]+)-([\w.]+)", re.I), "SSH", 2),

    # --- FTP ---
    (re.compile(r"220.*ProFTPD ([\w.]+)", re.I), "ProFTPD", 1),
    (re.compile(r"220.*vsFTPd ([\d.]+)", re.I), "vsFTPd", 1),
    (re.compile(r"220.*FileZilla Server ([\w.]+)", re.I), "FileZilla", 1),
    (re.compile(r"220[- ].*FTP", re.I), "FTP Server", None),

    # --- HTTP ---
    (re.compile(r"Server:\s*Apache/([\d.]+)", re.I), "Apache httpd", 1),
    (re.compile(r"Server:\s*nginx/([\d.]+)", re.I), "nginx", 1),
    (re.compile(r"Server:\s*Microsoft-IIS/([\d.]+)", re.I), "Microsoft IIS", 1),
    (re.compile(r"Server:\s*cloudflare", re.I), "Cloudflare (proxy)", None),
    (re.compile(r"Server:\s*([\w./-]+)", re.I), "HTTP Server", 1),

    # --- Mail ---
    (re.compile(r"^220[- ].*Postfix", re.I | re.M), "Postfix SMTP", None),
    (re.compile(r"^220[- ].*Exim ([\d.]+)", re.I | re.M), "Exim", 1),
    (re.compile(r"^220[- ].*Sendmail", re.I | re.M), "Sendmail", None),
    (re.compile(r"^\* OK.*Dovecot", re.I | re.M), "Dovecot IMAP", None),
    (re.compile(r"^\* OK.*IMAP", re.I | re.M), "IMAP Server", None),
    (re.compile(r"^\+OK.*POP3", re.I | re.M), "POP3 Server", None),

    # --- Veritabanları ---
    (re.compile(r"mysql_native_password", re.I), "MySQL", None),
    (re.compile(r"(\d+\.\d+\.\d+)-MariaDB", re.I), "MariaDB", 1),
    (re.compile(r"^R\x00\x00\x00", re.I), "PostgreSQL", None),
    (re.compile(r"MongoDB", re.I), "MongoDB", None),

    # --- Cache / NoSQL ---
    (re.compile(r"^\+PONG", re.I), "Redis", None),
    (re.compile(r"-NOAUTH Authentication required", re.I), "Redis (auth required)", None),
    (re.compile(r"^VERSION\s+([\w.]+)", re.I), "Memcached", 1),

    # --- Uzak erişim ---
    (re.compile(r"^RFB (\d{3}\.\d{3})", re.I), "VNC", 1),
    (re.compile(r"login:", re.I), "Telnet", None),

    # --- Diğer ---
    (re.compile(r"SMB", re.I), "SMB", None),
    (re.compile(r"^220.*ready", re.I), "Genel TCP Servis (220 ready)", None),
]

# Bilinen eski / riskli versiyonlar için çok basit bir "uyarı" sözlüğü.
RISK_KEYWORDS = {
    "vsftpd 2.3.4": "Bilinen backdoor içeren eski vsFTPd sürümü (örnek: CVE-2011-2523 kapsamı).",
    "openssh 4.": "Çok eski OpenSSH sürümü, güncellenmesi önerilir.",
    "openssh 5.": "Eski OpenSSH sürümü, güncellenmesi önerilir.",
    "apache httpd 2.2": "Desteği sonlanmış Apache 2.2 serisi.",
    "apache httpd 2.0": "Çok eski, desteği sonlanmış Apache 2.0 serisi.",
    "microsoft iis 6.0": "Desteği sonlanmış IIS 6.0.",
    "proftpd 1.3.3": "Bilinen backdoor içeren ProFTPD sürümü (örnek: CVE-2010-4221 kapsamı).",
}


def identify_service(banner: str, port: int = None, protocol: str = "tcp"):
    """
    Verilen banner metnini imzalarla karşılaştırır.
    Eşleşme yoksa, port numarasından bilinen servis ismini fallback olarak kullanır.

    Dönüş: dict {service, version, raw_banner, risk_note, source}
    source: "banner" (banner'dan tespit edildi) veya "port_guess" (sadece port no'dan tahmin)
    """
    if banner:
        for pattern, service_name, version_group in SIGNATURES:
            match = pattern.search(banner)
            if match:
                version = match.group(version_group) if version_group else None
                risk_note = _check_risk(service_name, version)
                return {
                    "service": service_name,
                    "version": version,
                    "raw_banner": banner.strip(),
                    "risk_note": risk_note,
                    "source": "banner",
                }

    # Banner yok ya da eşleşmedi: port numarasından tahmin et (nmap-services mantığı)
    if port is not None:
        guessed = guess_service_by_port(port, protocol)
        if guessed != "Bilinmiyor":
            return {
                "service": f"{guessed} (port tahmini)",
                "version": None,
                "raw_banner": (banner or "").strip(),
                "risk_note": None,
                "source": "port_guess",
            }

    return {
        "service": "Bilinmeyen",
        "version": None,
        "raw_banner": (banner or "").strip(),
        "risk_note": None,
        "source": "none",
    }


def _check_risk(service_name: str, version: str):
    if not version:
        return None
    key = f"{service_name.lower()} {version.lower()}"
    for risk_key, note in RISK_KEYWORDS.items():
        if key.startswith(risk_key):
            return note
    return None
