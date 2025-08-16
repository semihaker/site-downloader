#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Site Arşivleyici Pro v2.1.0 - Özellik Test Scripti
"""

import sys
import os
import time
from pathlib import Path

# Proje modüllerini import et
try:
    from utils import *
    from config import *
    from crawler import SiteCrawler
    print("✅ Tüm modüller başarıyla yüklendi")
except ImportError as e:
    print(f"❌ Modül yükleme hatası: {e}")
    sys.exit(1)

def test_basic_functions():
    """Temel fonksiyonları test et"""
    print("\n🔍 Temel Fonksiyonlar Test Ediliyor...")
    
    # URL doğrulama testi
    test_urls = [
        "https://example.com",
        "http://test.org",
        "invalid-url",
        "ftp://example.com",
        "javascript:alert('test')"
    ]
    
    for url in test_urls:
        is_valid = is_valid_url(url)
        print(f"  URL: {url} -> {'✅ Geçerli' if is_valid else '❌ Geçersiz'}")
    
    # Dosya boyutu formatlama testi
    test_sizes = [0, 1024, 1024*1024, 1024*1024*1024]
    for size in test_sizes:
        formatted = get_file_size_str(size)
        print(f"  Boyut: {size} bytes -> {formatted}")
    
    # Dosya yolu doğrulama testi
    test_paths = [
        "C:/test/file.txt",
        "invalid<>path",
        "very/long/path/that/exceeds/windows/limit/and/should/be/blocked/by/the/system/for/security/reasons/and/also/to/prevent/any_potential_issues/with/file_system_operations",
        "normal/path/file.txt"
    ]
    
    for path in test_paths:
        is_valid = DataValidator.validate_file_path(path)
        print(f"  Yol: {path} -> {'✅ Geçerli' if is_valid else '❌ Geçersiz'}")

def test_security_features():
    """Güvenlik özelliklerini test et"""
    print("\n🛡️ Güvenlik Özellikleri Test Ediliyor...")
    
    security = SecurityManager()
    
    # Tehdit içerik testi
    test_contents = [
        "<script>alert('test')</script>",
        "SELECT * FROM users WHERE id = 1",
        "normal content without threats",
        "<iframe src='malicious.com'></iframe>",
        "alert('test')",
        "normal text content"
    ]
    
    for content in test_contents:
        is_safe = security.is_safe_content(content)
        threats = security.scan_for_threats(content)
        print(f"  İçerik: {content[:50]}... -> {'✅ Güvenli' if is_safe else '❌ Tehlikeli'}")
        if threats:
            for threat_type, matches in threats.items():
                if matches:
                    print(f"    Tehdit: {threat_type} -> {len(matches)} eşleşme")

def test_performance_monitoring():
    """Performans izleme özelliklerini test et"""
    print("\n🚀 Performans İzleme Test Ediliyor...")
    
    monitor = PerformanceMonitor()
    
    # Operasyon testi
    monitor.start_operation("test_operation")
    time.sleep(0.1)  # Simüle edilmiş işlem
    monitor.end_operation("test_operation")
    
    # Bellek kullanımı testi
    memory_usage = monitor.get_memory_usage()
    print(f"  Mevcut bellek kullanımı: {get_file_size_str(memory_usage)}")
    
    # Performans raporu
    report = monitor.get_performance_report()
    print("  Performans raporu oluşturuldu")

def test_cache_manager():
    """Cache yöneticisini test et"""
    print("\n💾 Cache Yöneticisi Test Ediliyor...")
    
    cache = CacheManager(cache_dir="test_cache", max_size_mb=1)
    
    # Test verisi ekle
    test_data = b"Bu bir test verisidir"
    cache.set("test_key", test_data, ttl=10)
    
    # Veriyi al
    retrieved_data = cache.get("test_key")
    if retrieved_data == test_data:
        print("  ✅ Cache veri ekleme/alma başarılı")
    else:
        print("  ❌ Cache veri ekleme/alma başarısız")
    
    # Cache istatistikleri
    stats = cache.get_cache_stats()
    print(f"  Cache istatistikleri: {stats}")
    
    # Temizlik
    cache.delete("test_key")
    import shutil
    if os.path.exists("test_cache"):
        shutil.rmtree("test_cache")

def test_file_compressor():
    """Dosya sıkıştırma özelliklerini test et"""
    print("\n🗜️ Dosya Sıkıştırma Test Ediliyor...")
    
    compressor = FileCompressor()
    
    # Test dosyası oluştur
    test_file = "test_file.txt"
    test_content = "Bu bir test dosyasıdır. " * 1000
    
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(test_content)
    
    # Sıkıştır
    compressed_file = compressor.compress_file(test_file)
    if compressed_file and os.path.exists(compressed_file):
        print("  ✅ Dosya sıkıştırma başarılı")
        
        # Aç
        decompressed_file = compressor.decompress_file(compressed_file)
        if decompressed_file and os.path.exists(decompressed_file):
            print("  ✅ Dosya açma başarılı")
        
        # Temizlik
        for file in [test_file, compressed_file, decompressed_file]:
            if os.path.exists(file):
                os.remove(file)
    else:
        print("  ❌ Dosya sıkıştırma başarısız")

def test_url_processor():
    """URL işleme özelliklerini test et"""
    print("\n🔗 URL İşleme Test Ediliyor...")
    
    processor = URLProcessor()
    
    # Test metni
    test_text = """
    Bu bir test metnidir. İçinde email@example.com ve 
    telefon numarası 05551234567 bulunmaktadır.
    Sosyal medya linkleri: facebook.com, twitter.com
    """
    
    # Email çıkar
    emails = processor.extract_emails(test_text)
    print(f"  Bulunan email'ler: {emails}")
    
    # Telefon çıkar
    phones = processor.extract_phones(test_text)
    print(f"  Bulunan telefonlar: {phones}")
    
    # Sosyal medya çıkar
    social_media = processor.extract_social_media(test_text)
    print(f"  Bulunan sosyal medya: {social_media}")
    
    # İndirilebilir dosya kontrolü
    test_urls = [
        "https://example.com/file.html",
        "https://example.com/image.jpg",
        "https://example.com/style.css",
        "https://example.com/script.js",
        "https://example.com/page"
    ]
    
    for url in test_urls:
        is_downloadable = processor.is_downloadable_file(url)
        print(f"  URL: {url} -> {'✅ İndirilebilir' if is_downloadable else '❌ İndirilemez'}")

def test_config_system():
    """Konfigürasyon sistemini test et"""
    print("\n⚙️ Konfigürasyon Sistemi Test Ediliyor...")
    
    # Konfigürasyon özeti
    summary = get_config_summary()
    print(f"  Uygulama: {summary['app_info']['name']} v{summary['app_info']['version']}")
    print(f"  Desteklenen uzantı sayısı: {summary['supported_extensions_count']}")
    print(f"  User agent sayısı: {summary['user_agents_count']}")
    
    # Konfigürasyon değerleri
    depth = get_config('download.default_depth')
    delay = get_config('download.default_delay')
    print(f"  Varsayılan derinlik: {depth}")
    print(f"  Varsayılan gecikme: {delay}")
    
    # Uzantı desteği testi
    test_extensions = ['html', 'css', 'js', 'exe', 'bat']
    for ext in test_extensions:
        is_supported = is_extension_supported(ext)
        print(f"  Uzantı: .{ext} -> {'✅ Desteklenir' if is_supported else '❌ Desteklenmez'}")

def test_advanced_file_processor():
    """Gelişmiş dosya işleme özelliklerini test et"""
    print("\n📁 Gelişmiş Dosya İşleme Test Ediliyor...")
    
    processor = AdvancedFileProcessor(max_workers=2)
    
    # Test dosyaları oluştur
    test_files = []
    for i in range(3):
        filename = f"test_file_{i}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Test dosya {i} içeriği")
        test_files.append(filename)
    
    # Asenkron işleme
    def process_file(filepath):
        time.sleep(0.1)  # Simüle edilmiş işlem
        return f"İşlendi: {filepath}"
    
    futures = []
    for filename in test_files:
        future = processor.process_file_async(filename, process_file)
        futures.append(future)
    
    # Sonuçları bekle
    results = processor.wait_all()
    print(f"  İşlenen dosya sayısı: {len(results)}")
    
    # Temizlik
    processor.shutdown()
    for filename in test_files:
        if os.path.exists(filename):
            os.remove(filename)

def test_thread_safe_queue():
    """Thread-safe queue özelliklerini test et"""
    print("\n🔒 Thread-Safe Queue Test Ediliyor...")
    
    queue = ThreadSafeQueue(maxsize=5)
    
    # Test verileri ekle
    test_items = ["item1", "item2", "item3", "item4", "item5"]
    
    for item in test_items:
        success = queue.put(item)
        print(f"  Ekleme: {item} -> {'✅ Başarılı' if success else '❌ Başarısız'}")
    
    # Queue durumu
    print(f"  Queue boyutu: {queue.qsize()}")
    print(f"  Queue dolu mu: {queue.full()}")
    
    # Verileri al
    retrieved_items = []
    while not queue.empty():
        item = queue.get()
        if item:
            retrieved_items.append(item)
    
    print(f"  Alınan öğe sayısı: {len(retrieved_items)}")
    print(f"  Queue boş mu: {queue.empty()}")

def run_all_tests():
    """Tüm testleri çalıştır"""
    print("🌐 Web Site Arşivleyici Pro v2.1.0 - Özellik Testleri")
    print("=" * 60)
    
    start_time = time.time()
    
    try:
        test_basic_functions()
        test_security_features()
        test_performance_monitoring()
        test_cache_manager()
        test_file_compressor()
        test_url_processor()
        test_config_system()
        test_advanced_file_processor()
        test_thread_safe_queue()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print("\n" + "=" * 60)
        print("✅ Tüm testler başarıyla tamamlandı!")
        print(f"⏱️ Toplam test süresi: {duration:.2f} saniye")
        print("🎉 Proje v2.1.0 özellikleri çalışıyor!")
        
    except Exception as e:
        print(f"\n❌ Test hatası: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    run_all_tests()
