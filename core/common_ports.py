"""
Banner alınamadığında bile port numarasına bakarak muhtemel servis
tahmini yapmak için kullanılan tabloyu yazdık.
"""

TCP_COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS-SSN",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle-DB",
    2222: "SSH-Alt",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM-HTTP",
    6379: "Redis",
    6667: "IRC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

UDP_COMMON_PORTS = {
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    161: "SNMP",
    162: "SNMP-Trap",
    500: "IKE/IPsec",
    514: "Syslog",
    1900: "SSDP/UPnP",
    5353: "mDNS",
}


def guess_service_by_port(port: int, protocol: str = "tcp") -> str:
    table = TCP_COMMON_PORTS if protocol == "tcp" else UDP_COMMON_PORTS
    return table.get(port, "Bilinmiyor")
