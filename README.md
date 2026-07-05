# Mini Nmap

Basitleştirilmiş, eğitim amaçlı bir port tarayıcı ve banner grabbing aracı.
Python standart kütüphanesi dışında hiçbir bağımlılığı yoktur.

⚠️ **Yasal Uyarı:** Bu aracı yalnızca sahibi olduğunuz veya yazılı izniniz olan
sistemlerde kullanın. İzinsiz port taraması birçok ülkede suç teşkil edebilir.
SYN scan özellikle agresif/gizli bir teknik olduğu için buna dikkat edin.

## Kurulum

```bash
# Bağımlılık yok, sadece Python 3.8+ gerekli
cd mini_nmap
```

## Kullanım

```bash
# Basit TCP connect scan (varsayılan port 1-1024)
python scanner.py -t 192.168.1.10

# Gerçek SYN scan (yarı-açık tarama, ROOT gerektirir)
sudo python scanner.py -t 192.168.1.10 -p 1-1000 --scan-type syn

# UDP scan (DNS, NTP, SNMP gibi servisler)
python scanner.py -t 192.168.1.10 -p 53,123,161,500 --scan-type udp

# Belirli portlar, sonucu JSON'a kaydet
python scanner.py -t example.com -p 22,80,443 --output rapor.json

# Tüm portları çok thread ile tara, HTML rapor + OS tahmini
python scanner.py -t 127.0.0.1 -p 1-65535 --threads 300 --format html --output rapor.html --os-guess
```

## Parametreler

| Parametre | Açıklama |
|---|---|
| `-t / --target` | Hedef IP veya hostname (zorunlu) |
| `-p / --ports` | Port aralığı/listesi, örn `1-1000` veya `22,80,443` |
| `--scan-type` | `connect` (varsayılan), `syn` (root gerekir), `udp` |
| `--threads` | Paralel thread sayısı (varsayılan 100) |
| `--timeout` | Bağlantı zaman aşımı, saniye (varsayılan 1.0) |
| `--no-banner` | Sadece port tara, banner çekme |
| `--output` | Rapor dosya yolu |
| `--format` | `json`, `csv` veya `html` |
| `--os-guess` | TTL tabanlı kaba OS tahmini yap |

## Mimari

```
mini_nmap/
├── scanner.py              # CLI giriş noktası (3 tarama modunu yönetir)
├── core/
│   ├── port_scanner.py     # TCP connect scan (ThreadPoolExecutor)
│   ├── syn_scanner.py      # Raw socket ile gerçek SYN scan (root gerekir)
│   ├── udp_scanner.py      # UDP port tarama + protokole özel prob'lar
│   ├── banner_grabber.py   # Socket banner okuma + protokol probları
│   ├── fingerprint.py      # Regex tabanlı servis/versiyon tespiti
│   ├── common_ports.py     # Port -> servis adı fallback tablosu
│   └── os_guess.py         # TTL'den kaba OS tahmini
└── report/
    └── exporter.py         # JSON / CSV / HTML rapor üretimi
```

## Tarama Türleri Arasındaki Fark

### 1. TCP Connect Scan (`--scan-type connect`, varsayılan)
Her port için tam bir TCP el sıkışması (`connect()`) yapılır. Root gerektirmez,
her ortamda çalışır ama **her bağlantı loglanabilir** (hedef sistemin
log dosyalarında görünür).

### 2. TCP SYN Scan (`--scan-type syn`)
Raw socket ile elle inşa edilmiş bir SYN paketi gönderilir, tam bağlantı
**kurulmaz**. Hedef SYN-ACK ile cevap verirse port açık kabul edilir, ardından
işletim sistemimiz otomatik olarak RST göndererek bağlantıyı düşürür — bu
yüzden "yarı-açık" (half-open) scan olarak adlandırılır. Bu, nmap'in
öntanımlı ve en popüler tarama modudur (`-sS`).

**Gereksinim:** `sudo` ile çalıştırılmalıdır (raw socket = root/CAP_NET_RAW).
Root yoksa araç otomatik olarak TCP connect scan'e geri döner ve kullanıcıyı bilgilendirir.

### 3. UDP Scan (`--scan-type udp`)
UDP bağlantısız olduğu için sonuç üç durumdan biri olur:
- **open**: servis bir veri ile cevap verdi
- **closed**: ICMP "port unreachable" alındı
- **open|filtered**: hiç cevap gelmedi (belirsiz — servis mi yok saydı,
  firewall mu düşürdü bilinmiyor; nmap de aynı belirsizliği raporlar)

DNS (53) ve NTP (123) gibi bilinen servisler için gerçek protokol paketleri
gönderilir, böylece boş paketle cevap vermeyen servisler de tespit edilebilir.

## Nasıl Çalışır (genel akış)

1. **Port tarama**: Scan tipine göre `connect()`, elle SYN paketi veya UDP
   datagramı gönderilir.
2. **Banner grabbing**: Bağlantı kurulduktan sonra bazı servisler (SSH, FTP,
   Redis) kendiliğinden bir banner gönderir. HTTP/Redis/Memcached gibi
   servisler için önce küçük bir istek gönderilir.
3. **Fingerprinting**: Elde edilen banner, ~25 regex imzasıyla karşılaştırılır.
   Banner alınamazsa `common_ports.py` tablosundan port numarasına göre
   "muhtemel servis" tahmini yapılır (nmap-services mantığı).
4. **Risk notu**: Bilinen eski/riskli versiyonlar basit bir anahtar kelime
   sözlüğüyle işaretlenir (gerçek bir CVE veritabanı değildir).
5. **OS tahmini**: TTL değeri gözlemlenip en yakın standart başlangıç TTL
   değerine (64/128/255) yuvarlanarak kaba bir işletim sistemi tahmini yapılır.

## Sınırlamalar (nmap'e kıyasla)

- SYN scan sadece IPv4 destekler, IP spoofing/decoy yoktur.
- HTTPS/TLS servislerde banner grabbing basitleştirilmiştir (TLS handshake yapılmaz).
- OS tahmini çok kabadır; nmap'in çok katmanlı parmak izi analizine kıyasla güvenilir değildir.
- Servis imza veritabanı küçük bir alt kümedir (~25 imza); nmap'in binlerce imzası yoktur.
- NSE script motoru, zafiyet tarama veritabanı, timing/stealth ayarları (`-T0`..`-T5`) yoktur.
- Büyük ağları (/16, /8 gibi) verimli taramak için nmap'teki gibi gelişmiş
  zamanlama algoritmaları yoktur.

## Genişletme Fikirleri

- `core/fingerprint.py` içindeki `SIGNATURES` listesine yeni servisler eklemek
- IPv6 desteği eklemek
- Basit bir `--stealth` modu ile paketler arası gecikme eklemek (IDS atlatma)
- Sonuçları bir SQLite veritabanında geçmişe dönük saklamak (zaman içindeki
  değişimleri karşılaştırmak için)
