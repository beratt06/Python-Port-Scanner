"""
exporter.py
Tarama sonuçlarını JSON, CSV ve okunabilir bir HTML rapora dönüştürür.
nmap'in XML çıktısına kıyasla amaç: insan gözüyle kolay okunabilir çıktı.
"""

import json
import csv
import os
from datetime import datetime


def _ensure_dir(filepath: str):
    dirname = os.path.dirname(filepath)
    if dirname:
        os.makedirs(dirname, exist_ok=True)

def export_json(results: dict, filepath: str):
    _ensure_dir(filepath)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def export_csv(results: dict, filepath: str):
    _ensure_dir(filepath)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["port", "protocol", "state", "service", "version", "risk_note", "raw_banner"])
        for port_info in results.get("open_ports", []):
            writer.writerow([
                port_info.get("port"),
                port_info.get("protocol", "tcp"),
                port_info.get("state", "open"),
                port_info.get("service"),
                port_info.get("version"),
                port_info.get("risk_note"),
                port_info.get("raw_banner", "").replace("\n", " ").replace("\r", ""),
            ])


def export_html(results: dict, filepath: str):
    rows = ""
    for p in results.get("open_ports", []):
        risk = f'<span style="color:red;font-weight:bold;">{p.get("risk_note")}</span>' if p.get("risk_note") else "-"
        rows += f"""
        <tr>
            <td>{p.get('port')}/{p.get('protocol', 'tcp')}</td>
            <td>{p.get('state', 'open')}</td>
            <td>{p.get('service')}</td>
            <td>{p.get('version') or '-'}</td>
            <td>{risk}</td>
            <td><pre style="white-space:pre-wrap;">{_escape(p.get('raw_banner', ''))}</pre></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>Mini Nmap Tarama Raporu - {results.get('target')}</title>
<style>
    body {{ font-family: Arial, sans-serif; margin: 40px; background:#f7f7f9; }}
    h1 {{ color:#222; }}
    table {{ border-collapse: collapse; width: 100%; background:#fff; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align:left; vertical-align:top; }}
    th {{ background-color: #333; color:white; }}
    tr:nth-child(even) {{ background-color: #f2f2f2; }}
    .meta {{ margin-bottom: 20px; color:#555; }}
</style>
</head>
<body>
    <h1>Mini Nmap Tarama Raporu</h1>
    <div class="meta">
        <p><b>Hedef:</b> {results.get('target')}</p>
        <p><b>Tarama Tarihi:</b> {results.get('scan_time')}</p>
        <p><b>Taranan Port Sayısı:</b> {results.get('total_ports_scanned')}</p>
        <p><b>Açık Port Sayısı:</b> {len(results.get('open_ports', []))}</p>
        <p><b>Tahmini İşletim Sistemi:</b> {results.get('os_guess', 'Bilinmiyor')}</p>
    </div>
    <table>
        <tr><th>Port/Proto</th><th>Durum</th><th>Servis</th><th>Versiyon</th><th>Risk Notu</th><th>Ham Banner</th></tr>
        {rows}
    </table>
</body>
</html>"""

    _ensure_dir(filepath)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)


def _escape(text):
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_result_dict(target: str, open_ports_info: list, total_ports_scanned: int, os_guess: str = None):
    return {
        "target": target,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_ports_scanned": total_ports_scanned,
        "open_ports": open_ports_info,
        "os_guess": os_guess,
    }
