# 🌐 Web Site Arşivleyici Pro v2.1.0

**Profesyonel Web Site Arşivleme ve Yedekleme Çözümü**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.1.0-orange.svg)](CHANGELOG.md)

## 🚀 Özellikler

### ✨ Yeni Özellikler v2.1.0
- 🔒 **Gelişmiş Güvenlik Kontrolleri**: URL güvenlik doğrulaması, tehdit tarama
- 📊 **Performans İzleme**: Gerçek zamanlı performans takibi ve optimizasyon
- 💾 **Akıllı Cache Yönetimi**: Otomatik cache temizleme ve TTL desteği
- 🛡️ **Gelişmiş Hata Yönetimi**: Detaylı hata logları ve otomatik kurtarma
- 🌍 **Çoklu Dil Desteği**: Türkçe ve İngilizce dil desteği
- 🔄 **Otomatik Yedekleme**: Düzenli otomatik yedekleme sistemi
- 📈 **Gelişmiş Raporlama**: Detaylı indirme raporları ve istatistikler
- 🔍 **Akıllı Dosya Filtreleme**: Güvenli dosya türü kontrolü
- ⚡ **Performans Optimizasyonu**: Thread-safe queue ve asenkron işlemler

### 🎯 Temel Özellikler
- 🌐 **Modern Web Tarama**: Selenium ve BeautifulSoup ile gelişmiş site tarama
- 📁 **Akıllı Dosya Yönetimi**: Otomatik klasör yapısı ve dosya organizasyonu
- 🔗 **Derinlik Kontrollü Tarama**: Ayarlanabilir tarama derinliği
- ⏱️ **Gerçek Zamanlı İlerleme**: Canlı ilerleme takibi ve durum bildirimleri
- 🎨 **Modern Kullanıcı Arayüzü**: Dark tema ve kullanıcı dostu tasarım
- 📊 **Detaylı İstatistikler**: İndirilen dosya sayısı, boyut ve süre bilgileri
- 🔄 **Paralel İndirme**: Çoklu thread ile hızlı dosya indirme
- 💾 **Otomatik Yedekleme**: İndirme öncesi otomatik yedekleme

## 🛠️ Kurulum

### Gereksinimler
- Python 3.8 veya üzeri
- Google Chrome tarayıcısı
- Windows 10/11, macOS veya Linux

### Adım 1: Repository'yi Klonlayın
```bash
git clone https://github.com/username/site-downloader.git
cd site-downloader
```

### Adım 2: Sanal Ortam Oluşturun
```bash
python -m venv venv
```

### Windows
```bash
venv\Scripts\activate
```

### macOS/Linux
```bash
source venv/bin/activate
```

### Adım 3: Gerekli Paketleri Yükleyin
```bash
pip install -r requirements.txt
```

### Adım 4: Uygulamayı Çalıştırın
```bash
python main.py
```

## 📖 Kullanım

### 🎯 Basit Kullanım
1. **URL Girin**: Arşivlemek istediğiniz web sitesinin URL'sini girin
2. **Klasör Seçin**: İndirilen dosyaların kaydedileceği klasörü seçin
3. **Ayarları Yapın**: Tarama derinliği ve gecikme süresini ayarlayın
4. **Başlatın**: "Arşivlemeyi Başlat" butonuna tıklayın

### ⚙️ Gelişmiş Ayarlar
- **Tarama Derinliği**: 1-10 arası (varsayılan: 2)
- **Gecikme Süresi**: 0-60 saniye arası (varsayılan: 2s)
- **Dosya Türleri**: HTML, CSS, JS, resimler, PDF'ler
- **Maksimum Sayfa**: 20 sayfa (güvenlik için)
- **Thread Sayısı**: 1-20 arası paralel işlem

### 🔒 Güvenlik Özellikleri
- URL güvenlik doğrulaması
- Şüpheli domain engelleme
- Güvenli dosya türü kontrolü
- SSL sertifika doğrulaması
- Tehdit içerik tarama

## 🏗️ Proje Yapısı

```
site-downloader/
├── 📁 main.py              # Ana uygulama dosyası
├── 📁 gui.py               # Kullanıcı arayüzü
├── 📁 crawler.py           # Site tarama motoru
├── 📁 utils.py             # Yardımcı fonksiyonlar
├── 📁 config.py            # Konfigürasyon yönetimi
├── 📁 requirements.txt     # Python paketleri
├── 📁 README.md            # Bu dosya
├── 📁 CHANGELOG.md         # Değişiklik geçmişi
├── 📁 LICENSE              # Lisans dosyası
├── 📁 logs/                # Log dosyaları
├── 📁 downloads/           # İndirilen dosyalar
├── 📁 backups/             # Yedek dosyalar
└── 📁 cache/               # Cache dosyaları
```

## 🔧 Konfigürasyon

### Temel Ayarlar
```json
{
  "download": {
    "default_depth": 2,
    "default_delay": 2,
    "max_pages": 20,
    "timeout": 30
  },
  "performance": {
    "max_threads": 5,
    "enable_caching": true,
    "cache_size": 100
  },
  "security": {
    "enable_ssl_verification": true,
    "block_suspicious_urls": true,
    "scan_for_threats": true
  }
}
```

### Gelişmiş Ayarlar
- **Proxy Desteği**: HTTP/HTTPS proxy konfigürasyonu
- **Tor Desteği**: Anonim tarama için Tor entegrasyonu
- **Rate Limiting**: Sunucu yükünü azaltmak için hız sınırlama
- **Otomatik Temizlik**: Eski dosyaların otomatik temizlenmesi

## 📊 Performans

### Optimizasyonlar
- **Thread-Safe Queue**: Güvenli çoklu thread işlemleri
- **Asenkron Dosya İşleme**: Paralel dosya işleme
- **Akıllı Cache**: Otomatik cache yönetimi
- **Bellek Optimizasyonu**: Verimli bellek kullanımı

### Benchmark Sonuçları
- **Küçük Site (10 sayfa)**: ~30 saniye
- **Orta Site (50 sayfa)**: ~2-3 dakika
- **Büyük Site (100 sayfa)**: ~5-8 dakika

## 🚨 Sorun Giderme

### Yaygın Sorunlar

#### Chrome Bulunamadı
```bash
# Chrome'u yükleyin veya PATH'e ekleyin
# Windows: https://www.google.com/chrome/
# macOS: brew install --cask google-chrome
# Linux: sudo apt install google-chrome-stable
```

#### Bağımlılık Hataları
```bash
# Sanal ortamı yeniden oluşturun
rm -rf venv
python -m venv venv
source venv/bin/activate  # veya venv\Scripts\activate
pip install -r requirements.txt
```

#### İzin Hataları
```bash
# Klasör izinlerini kontrol edin
chmod 755 downloads/
chmod 755 logs/
```

### Log Dosyaları
- **Uygulama Logları**: `logs/app_YYYYMMDD_HHMMSS.log`
- **Site Raporları**: `downloads/[domain]/site_report.json`
- **Hata Detayları**: Log dosyalarında `ERROR` seviyesinde

## 🤝 Katkıda Bulunma

### Geliştirme Ortamı Kurulumu
1. Repository'yi fork edin
2. Feature branch oluşturun: `git checkout -b feature/yeni-ozellik`
3. Değişikliklerinizi commit edin: `git commit -am 'Yeni özellik eklendi'`
4. Branch'i push edin: `git push origin feature/yeni-ozellik`
5. Pull Request oluşturun

### Kod Standartları
- PEP 8 Python stil rehberine uyun
- Türkçe yorumlar kullanın
- Type hints ekleyin
- Unit testler yazın
- Dokümantasyon güncelleyin

## 📝 Changelog

### v2.1.0 (2024-01-XX)
- ✨ Gelişmiş güvenlik kontrolleri eklendi
- 🚀 Performans izleme ve optimizasyon
- 💾 Akıllı cache yönetimi
- 🛡️ Gelişmiş hata yönetimi
- 🌍 Çoklu dil desteği
- 🔄 Otomatik yedekleme sistemi

### v2.0.0 (2024-01-XX)
- 🎨 Modern kullanıcı arayüzü
- 🔗 Gelişmiş site tarama
- ⚡ Paralel dosya indirme
- 📊 Gerçek zamanlı ilerleme takibi

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 👥 Geliştirici 

- **Ana Geliştirici**: [Semih](akersemih07@gmail.com)


## 🙏 Teşekkürler

- [Selenium](https://selenium.dev/) - Web otomasyon
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) - HTML parsing
- [Requests](https://requests.readthedocs.io/) - HTTP kütüphanesi
- [Tkinter](https://docs.python.org/3/library/tkinter.html) - GUI framework



## ⭐ Projeyi Beğendiyseniz

Bu projeyi beğendiyseniz, GitHub'da ⭐ vermeyi unutmayın! Bu, projeyi geliştirmeye devam etmemiz için büyük motivasyon sağlar.

---

**Web Site Arşivleyici Pro** ile web sitelerinizi güvenle arşivleyin! 🚀

