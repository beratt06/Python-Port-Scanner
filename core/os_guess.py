"""
os_guess.py
TTL (Time To Live) değerine bakarak ÇOK kaba bir işletim sistemi tahmini yapar.
Bu, nmap'in gelişmiş OS fingerprinting (-O) özelliğinin ciddi şekilde
basitleştirilmiş bir taklididir ve kesin sonuç vermez; sadece fikir verir.

Genel bilinen varsayılan TTL değerleri:
- Linux/Unix: 64
- Windows: 128
- Bazı router/network cihazları: 255
Ağ üzerindeki her hop TTL'yi 1 azalttığı için gerçek başlangıç değeri
gözlemlenen değere en yakın "standart" değere yuvarlanarak tahmin edilir.
"""

COMMON_INITIAL_TTLS = [64, 128, 255]


def guess_os(ttl):
    if ttl is None:
        return "Bilinmiyor (TTL alınamadı)"

    closest = min(COMMON_INITIAL_TTLS, key=lambda x: abs(x - ttl) if ttl <= x else float("inf"))

    mapping = {
        64: "Linux / Unix / macOS (tahmini)",
        128: "Windows (tahmini)",
        255: "Ağ cihazı / Router / Bazı Unix türevleri (tahmini)",
    }
    return mapping.get(closest, "Bilinmiyor")
