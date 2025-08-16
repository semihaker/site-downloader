#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Site Arşivleyici Pro - Ana Uygulama
Versiyon: 2.1.0
Açıklama: Profesyonel web site arşivleme ve yedekleme uygulaması
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox
import subprocess
import importlib.util
import logging
import traceback
from pathlib import Path
import json
import time
from datetime import datetime

# Loglama sistemini başlat
def setup_logging():
    """Loglama sistemini kur"""
    try:
        # Log dizinini oluştur
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Log dosya adı
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"app_{timestamp}.log"
        
        # Loglama formatı
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        logging.info(f"Loglama sistemi başlatıldı: {log_file}")
        return True
        
    except Exception as e:
        print(f"Loglama sistemi başlatılamadı: {e}")
        return False

def check_python_version():
    """Python versiyonunu kontrol et"""
    try:
        if sys.version_info < (3, 8):
            messagebox.showerror(
                "Python Versiyon Hatası",
                "Bu uygulama Python 3.8 veya üzeri gerektirir.\n"
                f"Mevcut versiyon: {sys.version}\n\n"
                "Lütfen Python'u güncelleyin."
            )
            logging.error(f"Python versiyon hatası: {sys.version}")
            return False
        
        logging.info(f"Python versiyonu uygun: {sys.version}")
        return True
        
    except Exception as e:
        logging.error(f"Python versiyon kontrolü hatası: {e}")
        return False

def check_dependencies():
    """Gerekli paketlerin kurulu olup olmadığını kontrol et"""
    required_packages = [
        'requests',
        'beautifulsoup4', 
        'selenium',
        'lxml',
        'psutil'
    ]
    
    missing_packages = []
    optional_packages = []
    
    for package in required_packages:
        try:
            if package == 'beautifulsoup4':
                import bs4
                logging.info(f"✅ {package} yüklendi")
            elif package == 'lxml':
                import lxml
                logging.info(f"✅ {package} yüklendi")
            elif package == 'psutil':
                import psutil
                logging.info(f"✅ {package} yüklendi")
            else:
                importlib.import_module(package)
                logging.info(f"✅ {package} yüklendi")
        except ImportError:
            missing_packages.append(package)
            logging.warning(f"❌ {package} eksik")
    
    # Opsiyonel paketleri kontrol et
    optional_packages_list = ['pillow', 'aiohttp', 'cryptography']
    for package in optional_packages_list:
        try:
            importlib.import_module(package)
            logging.info(f"✅ {package} (opsiyonel) yüklendi")
        except ImportError:
            optional_packages.append(package)
            logging.info(f"ℹ️ {package} (opsiyonel) yüklenmedi")
    
    if missing_packages:
        error_msg = f"Aşağıdaki paketler eksik:\n{', '.join(missing_packages)}\n\n"
        error_msg += "Lütfen şu komutu çalıştırın:\n"
        error_msg += "pip install -r requirements.txt"
        
        messagebox.showerror("Eksik Paketler", error_msg)
        logging.error(f"Eksik paketler: {missing_packages}")
        return False
    
    if optional_packages:
        logging.info(f"Opsiyonel paketler yüklenmedi: {optional_packages}")
    
    logging.info("Tüm gerekli paketler yüklendi")
    return True

def check_chrome():
    """Chrome tarayıcısının kurulu olup olmadığını kontrol et"""
    try:
        # Windows için Chrome kontrolü
        if os.name == 'nt':
            chrome_paths = [
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                os.path.expanduser(r"~\AppData\Local\Google\Chrome\Application\chrome.exe"),
                r"C:\Program Files\Google\Chrome Beta\Application\chrome.exe",
                r"C:\Program Files\Google\Chrome SxS\Application\chrome.exe"
            ]
            
            for path in chrome_paths:
                if os.path.exists(path):
                    logging.info(f"Chrome bulundu: {path}")
                    return True
            
            # Registry'den kontrol et
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe")
                winreg.CloseKey(key)
                logging.info("Chrome registry'de bulundu")
                return True
            except:
                pass
                
        else:
            # Linux/macOS için
            result = subprocess.run(['which', 'google-chrome'], capture_output=True, text=True)
            if result.returncode == 0:
                logging.info(f"Chrome bulundu: {result.stdout.strip()}")
                return True
            
            result = subprocess.run(['which', 'chrome'], capture_output=True, text=True)
            if result.returncode == 0:
                logging.info(f"Chrome bulundu: {result.stdout.strip()}")
                return True
        
        logging.warning("Chrome bulunamadı")
        return False
        
    except Exception as e:
        logging.error(f"Chrome kontrolü hatası: {e}")
        return False

def check_system_requirements():
    """Sistem gereksinimlerini kontrol et"""
    try:
        import psutil
        
        # RAM kontrolü
        memory = psutil.virtual_memory()
        memory_gb = memory.total / (1024**3)
        
        if memory_gb < 2:
            logging.warning(f"Düşük RAM: {memory_gb:.1f} GB (önerilen: 4+ GB)")
        
        # Disk alanı kontrolü
        disk = psutil.disk_usage('/')
        disk_gb = disk.free / (1024**3)
        
        if disk_gb < 1:
            logging.warning(f"Düşük disk alanı: {disk_gb:.1f} GB (önerilen: 5+ GB)")
        
        # CPU kontrolü
        cpu_count = psutil.cpu_count()
        if cpu_count < 2:
            logging.warning(f"Düşük CPU çekirdek sayısı: {cpu_count} (önerilen: 2+)")
        
        logging.info(f"Sistem bilgileri - RAM: {memory_gb:.1f} GB, Disk: {disk_gb:.1f} GB, CPU: {cpu_count}")
        return True
        
    except Exception as e:
        logging.error(f"Sistem gereksinimleri kontrolü hatası: {e}")
        return False

def create_directories():
    """Gerekli dizinleri oluştur"""
    try:
        directories = [
            "logs",
            "downloads", 
            "backups",
            "cache",
            "temp"
        ]
        
        for directory in directories:
            Path(directory).mkdir(exist_ok=True)
            logging.info(f"Dizin oluşturuldu: {directory}")
        
        return True
        
    except Exception as e:
        logging.error(f"Dizin oluşturma hatası: {e}")
        return False

def load_settings():
    """Ayarları yükle"""
    try:
        if os.path.exists('settings.json'):
            with open('settings.json', 'r', encoding='utf-8') as f:
                settings = json.load(f)
                logging.info("Ayarlar yüklendi")
                return settings
        else:
            # Varsayılan ayarları oluştur
            default_settings = {
                'default_depth': '2',
                'default_delay': '2',
                'default_file_types': 'Tümü',
                'theme': 'dark',
                'auto_save': True,
                'language': 'tr',
                'last_used_directory': str(Path.home()),
                'show_welcome_message': True
            }
            
            with open('settings.json', 'w', encoding='utf-8') as f:
                json.dump(default_settings, f, indent=2, ensure_ascii=False)
            
            logging.info("Varsayılan ayarlar oluşturuldu")
            return default_settings
            
    except Exception as e:
        logging.error(f"Ayarlar yükleme hatası: {e}")
        return {}

def show_welcome_message():
    """Hoş geldin mesajı göster"""
    try:
        messagebox.showinfo(
            "🌐 Web Site Arşivleyici Pro v2.1.0",
            "🚀 Web Site Arşivleyici Pro'ya Hoş Geldiniz!\n\n"
            "Bu uygulama ile web sitelerinizi kolayca arşivleyebilir ve yedekleyebilirsiniz.\n\n"
            "✨ Yeni Özellikler v2.1.0:\n"
            "• Gelişmiş güvenlik kontrolleri\n"
            "• Performans izleme ve optimizasyon\n"
            "• Akıllı cache yönetimi\n"
            "• Gelişmiş hata yönetimi\n"
            "• Çoklu dil desteği\n"
            "• Otomatik yedekleme\n\n"
            "Başlamak için bir URL girin ve klasör seçin!"
        )
        logging.info("Hoş geldin mesajı gösterildi")
        
    except Exception as e:
        logging.error(f"Hoş geldin mesajı hatası: {e}")

def show_error_dialog(error_msg, error_details=None):
    """Hata dialog'u göster"""
    try:
        if error_details:
            error_msg += f"\n\nDetaylar:\n{error_details}"
        
        messagebox.showerror("Hata", error_msg)
        logging.error(f"Hata dialog'u gösterildi: {error_msg}")
        
    except Exception as e:
        logging.error(f"Hata dialog'u hatası: {e}")

def main():
    """Ana uygulama fonksiyonu"""
    start_time = time.time()
    
    try:
        logging.info("=" * 60)
        logging.info("Web Site Arşivleyici Pro başlatılıyor...")
        logging.info(f"Başlangıç zamanı: {datetime.now()}")
        
        # Loglama sistemini başlat
        if not setup_logging():
            print("Loglama sistemi başlatılamadı, devam ediliyor...")
        
        # Python versiyon kontrolü
        if not check_python_version():
            sys.exit(1)
        
        # Sistem gereksinimleri kontrolü
        check_system_requirements()
        
        # Bağımlılık kontrolü
        if not check_dependencies():
            sys.exit(1)
        
        # Chrome kontrolü
        chrome_available = check_chrome()
        if not chrome_available:
            result = messagebox.askyesno(
                "Chrome Bulunamadı",
                "Google Chrome tarayıcısı bulunamadı.\n\n"
                "Chrome kurulu değilse, lütfen önce Chrome'u kurun.\n\n"
                "Chrome kuruluysa, uygulamayı yine de çalıştırmak istiyor musunuz?"
            )
            if not result:
                logging.info("Kullanıcı Chrome olmadan çalıştırmayı reddetti")
                sys.exit(1)
            else:
                logging.warning("Chrome olmadan uygulama çalıştırılıyor")
        
        # Gerekli dizinleri oluştur
        create_directories()
        
        # Ayarları yükle
        settings = load_settings()
        
        # GUI'yi import et
        try:
            from gui import ModernSiteDownloader
            logging.info("GUI modülü başarıyla yüklendi")
        except ImportError as e:
            logging.error(f"GUI modülü yüklenemedi: {e}")
            show_error_dialog(
                "GUI Modülü Hatası",
                f"Gerekli GUI modülü yüklenemedi:\n{str(e)}\n\n"
                "Lütfen requirements.txt dosyasındaki paketleri yükleyin."
            )
            sys.exit(1)
        
        # Hoş geldin mesajı (ayarlardan kontrol et)
        if settings.get('show_welcome_message', True):
            show_welcome_message()
        
        # Uygulamayı başlat
        logging.info("GUI başlatılıyor...")
        app = ModernSiteDownloader()
        
        # Uygulama çalışma süresini hesapla
        run_time = time.time() - start_time
        logging.info(f"Uygulama başlatıldı, süre: {run_time:.2f} saniye")
        
        # GUI'yi çalıştır
        app.run()
        
    except ImportError as e:
        error_msg = f"Gerekli modül yüklenemedi:\n{str(e)}\n\n"
        error_msg += "Lütfen requirements.txt dosyasındaki paketleri yükleyin."
        
        logging.error(f"Import hatası: {e}")
        show_error_dialog("Import Hatası", error_msg)
        sys.exit(1)
        
    except Exception as e:
        error_msg = f"Uygulama başlatılırken bir hata oluştu:\n{str(e)}"
        error_details = traceback.format_exc()
        
        logging.error(f"Beklenmeyen hata: {e}")
        logging.error(f"Hata detayları:\n{error_details}")
        
        show_error_dialog(error_msg, error_details)
        sys.exit(1)
    
    finally:
        # Uygulama kapanırken temizlik yap
        try:
            logging.info("Uygulama kapatılıyor...")
            logging.info("=" * 60)
        except:
            pass

if __name__ == "__main__":
    # Uygulama başlatılıyor
    main()
