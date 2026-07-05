# Python Port Scanner 🔍

Ağ programlama, soket (socket) yapıları ve siber güvenlik konseptlerini (TCP/UDP handshake, Raw Sockets, Banner Grabbing) daha iyi kavramak amacıyla **tamamen sıfırdan ve eğitim amaçlı** geliştirdiğim Python tabanlı bir Nmap klonudur. Proje, standart Python kütüphaneleri kullanılarak geliştirilmiş olup harici bir bağımlılık (dependency) barındırmaz.

⚠️ **Yasal Uyarı:** Bu araç sadece eğitim, defansif güvenlik testleri ve ağ mimarilerini anlamak için yazılmıştır. Lütfen yalnızca kendi ağınızda veya yetkili olduğunuz sistemlerde kullanın. İzinsiz taramalar yasal sorumluluk doğurabilir.

---

## 🚀 Özellikler

- **Çoklu Tarama Modları:** 
  - `TCP Connect Scan (-sT)`: Tam el sıkışmalı, güvenilir tarama.
  - `TCP SYN Scan (-sS)`: Raw socket (ham soket) kullanılarak yapılan yarı-açık (gizli) tarama (Root/Admin yetkisi gerektirir).
  - `UDP Scan (-sU)`: Bağlantısız UDP portlarının protokole özel problarla (DNS, NTP vb.) taranması.
- **Banner Grabbing & Fingerprinting:** Açık portlardaki servislere özel problar göndererek çalışan servisin markasını ve versiyonunu tespit etme.
- **İşletim Sistemi Tahmini:** Hedefin TTL (Time To Live) değerine bakarak kaba OS analizi (Linux, Windows, Network Cihazı).
- **Çoklu İş Parçacığı (Multi-threading):** Ağ taramalarını hızlandırmak için `ThreadPoolExecutor` destekli asenkron yapı.
- **Detaylı Raporlama:** Sonuçları `JSON`, `CSV` ve `HTML` (görsel tablo) formatlarında dışa aktarabilme.

---

## 🛠️ Kurulum

Proje Python 3.8 ve üzeri sürümlerde çalışacak şekilde tasarlanmıştır. Herhangi bir `pip install` işlemine gerek yoktur.

```bash
# Repoyu bilgisayarınıza klonlayın
git clone https://github.com/beratt06/Python-Port-Scanner.git

# Proje dizinine girin
cd Python-Port-Scanner
```

---

## 💻 Kullanım Örnekleri

Aşağıdaki komutları kendi terminalinizde (veya CMD/PowerShell) çalıştırarak aracı test edebilirsiniz.

**1. Basit Tarama (Varsayılan olarak ilk 1024 portu tarar):**
```bash
python scanner.py -t 192.168.1.10
```

**2. Gerçek SYN (Yarı-Açık) Taraması (Gizlilik Modu):**
*(Not: Raw soket kullanıldığı için Linux'ta `sudo`, Windows'ta Yönetici olarak çalıştırılmalıdır)*
```bash
sudo python scanner.py -t 192.168.1.10 -p 1-1000 --scan-type syn
```

**3. UDP Taraması (Örn: DNS, NTP servisleri):**
```bash
python scanner.py -t 192.168.1.10 -p 53,123,161 --scan-type udp
```

**4. Tam Teşekküllü Tarama & HTML Rapor Alma:**
*(Tüm portları, 300 thread hızıyla tara, OS tahmini yap ve HTML olarak kaydet)*
```bash
python scanner.py -t example.com -p 1-65535 --threads 300 --format html --output raporlar/sonuc.html --os-guess
```

---

## ⚙️ Parametre Tablosu

| Parametre | Ne İşe Yarar? |
| :--- | :--- |
| `-t, --target` | Hedef IP adresi veya alan adı (Örn: `10.0.0.1` veya `google.com`) **[Zorunlu]** |
| `-p, --ports` | Taranacak port aralığı (Örn: `1-1000` veya `22,80,443`) |
| `--scan-type` | Tarama yöntemi: `connect` (Varsayılan), `syn` veya `udp` |
| `--threads` | Hızı belirleyen eşzamanlı işlem sayısı (Varsayılan: `100`) |
| `--timeout` | Bir porta bağlanmak için beklenecek maksimum süre (Varsayılan: `1.0` saniye) |
| `--no-banner` | Servis versiyonlarını okumayı atlayarak taramayı hızlandırır |
| `--output` | Raporun kaydedileceği dosya yolu (Örn: `cikti.json`) |
| `--format` | Dışa aktarma formatı: `json`, `csv` veya `html` |
| `--os-guess` | Hedefe Ping atarak dönen TTL değerine göre İşletim Sistemi tahmini yapar |

---

## 📂 Kod Mimarisi

Öğrenim sürecimde kodları olabildiğince modüler tutmaya çalıştım:

```text
Python-Port-Scanner/
├── scanner.py              # Ana giriş noktası (Argümanları işler ve orkestrasyonu sağlar)
├── core/
│   ├── port_scanner.py     # Standart TCP Connect tarayıcı motoru
│   ├── syn_scanner.py      # TCP SYN paketlerini el ile (Raw Socket) inşa eden motor
│   ├── udp_scanner.py      # ICMP hata yakalamalı UDP tarayıcı motoru
│   ├── banner_grabber.py   # Açık portlardan SSL destekli banner okuyucu
│   ├── fingerprint.py      # Regex ile versiyon ve marka ayrıştıran analizci
│   ├── common_ports.py     # Nmap-services tarzı port tahmin tablosu
│   └── os_guess.py         # Subprocess ile PING atıp TTL analiz eden modül
└── report/
    └── exporter.py         # Çıktıları JSON/CSV/HTML tablolarına dönüştüren modül
```

---

## 📝 Gelecek Geliştirmeler (TODO)
Öğrencilik serüvenim boyunca bu projeye eklemeyi planladığım özellikler:
- [ ] IPv6 Desteği
- [ ] Tarama süresini optimize etmek için hedefi paket yağmuruna tutmayan `--stealth` (gecikmeli) mod
- [ ] Gelişmiş bir CVE (Zafiyet) veritabanı API bağlantısı ile tespit edilen versiyonlarda açık olup olmadığını sorgulama

---
*Bu proje, Ağ Protokolleri ve Siber Güvenlik dünyasına atılan bir adım olarak geliştirilmiştir. Katkı ve tavsiyelere her zaman açıktır!*
