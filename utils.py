#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Site Arşivleyici Pro - Yardımcı Fonksiyonlar
Versiyon: 2.1.0
"""

import os
import hashlib
import mimetypes
import urllib.parse
from datetime import datetime
import re
import json
from pathlib import Path
import logging
import threading
import time
import hashlib
import shutil
from typing import Optional, Dict, List, Union, Tuple
import zipfile
import tarfile
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import gzip

# Gelişmiş loglama sistemi
class AdvancedLogger:
    def __init__(self, log_file: str = "site_downloader.log", level: int = logging.INFO):
        self.logger = logging.getLogger("SiteDownloader")
        self.logger.setLevel(level)
        
        # Dosya handler'ı
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        
        # Console handler'ı
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        
        # Format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def debug(self, message: str):
        self.logger.debug(message)

# Global logger instance
logger = AdvancedLogger()

def sanitize_filename(filename: str) -> str:
    """Dosya adını güvenli hale getir - Gelişmiş versiyon"""
    if not filename:
        return "unnamed_file"
    
    # Geçersiz karakterleri kaldır
    filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
    
    # Çok uzun dosya adlarını kısalt
    if len(filename) > 200:
        name, ext = os.path.splitext(filename)
        filename = name[:200-len(ext)] + ext
    
    # Boş dosya adı kontrolü
    if not filename.strip():
        filename = "unnamed_file"
    
    return filename

def get_file_size_str(size_bytes: int) -> str:
    """Byte cinsinden boyutu okunabilir formata çevir - Gelişmiş versiyon"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    # Daha hassas formatlama
    if size_bytes >= 100:
        return f"{size_bytes:.0f} {size_names[i]}"
    else:
        return f"{size_bytes:.1f} {size_names[i]}"

def calculate_folder_size(folder_path: str) -> Tuple[int, Dict[str, int]]:
    """Klasör boyutunu hesapla - Detaylı analiz ile"""
    total_size = 0
    file_types = {}
    
    try:
        for dirpath, dirnames, filenames in os.walk(folder_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    try:
                        file_size = os.path.getsize(filepath)
                        total_size += file_size
                        
                        # Dosya tipi analizi
                        ext = os.path.splitext(filename)[1].lower()
                        if ext in file_types:
                            file_types[ext] += file_size
                        else:
                            file_types[ext] = file_size
                    except (OSError, PermissionError):
                        logger.warning(f"Dosya boyutu alınamadı: {filepath}")
                        continue
    except Exception as e:
        logger.error(f"Klasör boyutu hesaplanamadı: {e}")
    
    return total_size, file_types

def get_file_hash(filepath: str, algorithm: str = 'sha256') -> Optional[str]:
    """Dosya hash'ini hesapla - Gelişmiş algoritma desteği"""
    try:
        if algorithm not in hashlib.algorithms_available:
            algorithm = 'sha256'  # Varsayılan
        
        hash_func = getattr(hashlib, algorithm)()
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):  # Daha büyük chunk
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    except Exception as e:
        logger.error(f"Hash hesaplanamadı {filepath}: {e}")
        return None

def is_valid_url(url: str) -> bool:
    """URL'nin geçerli olup olmadığını kontrol et - Gelişmiş validasyon"""
    if not url or not isinstance(url, str):
        return False
    
    try:
        result = urllib.parse.urlparse(url)
        
        # Scheme kontrolü
        if result.scheme not in ['http', 'https']:
            return False
        
        # Domain kontrolü
        if not result.netloc or len(result.netloc) < 3:
            return False
        
        # IP adresi kontrolü (basit)
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', result.netloc):
            return True
        
        # Domain format kontrolü
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, result.netloc):
            return False
        
        return True
    except Exception:
        return False

def normalize_url(url: str) -> str:
    """URL'yi normalize et - Gelişmiş normalizasyon"""
    if not url:
        return ""
    
    # Boşlukları temizle
    url = url.strip()
    
    # Scheme ekle
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # www. ekle (eğer yoksa)
    parsed = urllib.parse.urlparse(url)
    if not parsed.netloc.startswith('www.') and '.' in parsed.netloc:
        url = url.replace(parsed.netloc, 'www.' + parsed.netloc, 1)
    
    # Trailing slash ekle
    if not url.endswith('/'):
        url += '/'
    
    return url

def get_domain_from_url(url: str) -> Optional[str]:
    """URL'den domain'i çıkar - Gelişmiş parsing"""
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        # www. kaldır
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain
    except Exception:
        return None

def is_same_domain(url1: str, url2: str) -> bool:
    """İki URL'nin aynı domain'de olup olmadığını kontrol et"""
    domain1 = get_domain_from_url(url1)
    domain2 = get_domain_from_url(url2)
    
    if not domain1 or not domain2:
        return False
    
    return domain1 == domain2

def get_file_extension_from_url(url: str, content_type: Optional[str] = None) -> str:
    """URL'den dosya uzantısını belirle - Gelişmiş algılama"""
    # URL'den uzantı al
    parsed = urllib.parse.urlparse(url)
    path = parsed.path
    
    if '.' in path:
        ext = path.split('.')[-1].lower()
        # Daha fazla dosya tipi desteği
        valid_extensions = [
            'html', 'htm', 'css', 'js', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'ico', 
            'pdf', 'txt', 'xml', 'json', 'csv', 'zip', 'rar', '7z', 'mp4', 'mp3',
            'avi', 'mov', 'wmv', 'flv', 'webm', 'ogg', 'wav', 'flac', 'doc', 'docx',
            'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'odt', 'ods', 'odp'
        ]
        if ext in valid_extensions:
            return ext
    
    # Content-Type'dan uzantı al
    if content_type:
        ext = mimetypes.guess_extension(content_type)
        if ext:
            return ext.lstrip('.')
    
    # Varsayılan HTML
    return 'html'

def create_safe_path(base_path: str, url_path: str) -> str:
    """Güvenli dosya yolu oluştur - Gelişmiş güvenlik"""
    if not url_path:
        url_path = "index.html"
    
    # URL path'ini temizle
    safe_path = re.sub(r'[<>:"|?*\x00-\x1f]', '_', url_path)
    
    # Çok uzun path'leri kısalt
    if len(safe_path) > 200:
        name, ext = os.path.splitext(safe_path)
        safe_path = name[:200-len(ext)] + ext
    
    # Tam yolu oluştur
    full_path = os.path.join(base_path, safe_path)
    
    # Klasörleri oluştur
    try:
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
    except Exception as e:
        logger.error(f"Klasör oluşturulamadı: {e}")
        # Alternatif yol oluştur
        alt_path = os.path.join(base_path, "fallback", safe_path)
        os.makedirs(os.path.dirname(alt_path), exist_ok=True)
        return alt_path
    
    return full_path

def format_timestamp(timestamp=None) -> str:
    """Zaman damgasını formatla - Gelişmiş formatlama"""
    if timestamp is None:
        timestamp = datetime.now()
    
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except:
            timestamp = datetime.now()
    
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")

def format_duration(seconds: float) -> str:
    """Saniyeyi okunabilir süreye çevir - Gelişmiş formatlama"""
    if seconds < 0:
        return "0s"
    
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        seconds = seconds % 60
        return f"{minutes}m {seconds:.1f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        seconds = seconds % 60
        return f"{hours}h {minutes}m {seconds:.1f}s"

def create_backup_filename(original_path: str) -> str:
    """Yedek dosya adı oluştur - Gelişmiş timestamp"""
    base, ext = os.path.splitext(original_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]  # Mikrosaniye dahil
    return f"{base}_backup_{timestamp}{ext}"

def is_binary_file(filepath: str) -> bool:
    """Dosyanın binary olup olmadığını kontrol et - Gelişmiş algılama"""
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(1024)
            # Daha gelişmiş binary detection
            return b'\x00' in chunk or any(byte < 32 and byte not in [9, 10, 13] for byte in chunk)
    except Exception:
        return False

def get_mime_type(filepath: str) -> Optional[str]:
    """Dosya MIME type'ını al - Gelişmiş algılama"""
    try:
        # Önce dosya uzantısından tahmin et
        mime_type, _ = mimetypes.guess_type(filepath)
        
        if mime_type:
            return mime_type
        
        # Özel dosya tipleri
        ext = os.path.splitext(filepath)[1].lower()
        mime_map = {
            '.py': 'text/x-python',
            '.js': 'application/javascript',
            '.css': 'text/css',
            '.html': 'text/html',
            '.htm': 'text/html',
            '.xml': 'application/xml',
            '.json': 'application/json',
            '.md': 'text/markdown',
            '.txt': 'text/plain',
            '.log': 'text/plain'
        }
        
        return mime_map.get(ext, 'application/octet-stream')
        
    except Exception:
        return None

def create_directory_structure(base_path: str, structure: List[str]) -> bool:
    """Klasör yapısını oluştur - Hata yönetimi ile"""
    try:
        for folder in structure:
            folder_path = os.path.join(base_path, folder)
            os.makedirs(folder_path, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Klasör yapısı oluşturulamadı: {e}")
        return False

def save_json_data(data: dict, filepath: str, indent: int = 2) -> bool:
    """JSON verisini dosyaya kaydet - Gelişmiş hata yönetimi"""
    try:
        # Yedek oluştur
        if os.path.exists(filepath):
            backup_path = create_backup_filename(filepath)
            shutil.copy2(filepath, backup_path)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False, default=str)
        
        logger.info(f"JSON verisi kaydedildi: {filepath}")
        return True
    except Exception as e:
        logger.error(f"JSON kaydedilemedi {filepath}: {e}")
        return False

def load_json_data(filepath: str) -> Optional[dict]:
    """JSON verisini dosyadan yükle - Gelişmiş hata yönetimi"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        logger.warning(f"JSON dosyası bulunamadı: {filepath}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"JSON parse hatası {filepath}: {e}")
        # Yedek dosyayı dene
        backup_files = [f for f in os.listdir(os.path.dirname(filepath)) 
                       if f.startswith(os.path.basename(filepath)) and 'backup' in f]
        if backup_files:
            latest_backup = sorted(backup_files)[-1]
            backup_path = os.path.join(os.path.dirname(filepath), latest_backup)
            logger.info(f"Yedek dosyadan yükleniyor: {backup_path}")
            return load_json_data(backup_path)
        return None
    except Exception as e:
        logger.error(f"JSON yüklenemedi {filepath}: {e}")
        return None

def get_file_info(filepath: str) -> Optional[Dict]:
    """Dosya bilgilerini al - Gelişmiş bilgi toplama"""
    try:
        stat = os.stat(filepath)
        
        # Hash hesapla
        file_hash = get_file_hash(filepath)
        
        # MIME type
        mime_type = get_mime_type(filepath)
        
        # Binary kontrol
        is_binary = is_binary_file(filepath)
        
        return {
            'size': stat.st_size,
            'size_str': get_file_size_str(stat.st_size),
            'created': datetime.fromtimestamp(stat.st_ctime),
            'modified': datetime.fromtimestamp(stat.st_mtime),
            'accessed': datetime.fromtimestamp(stat.st_atime),
            'is_file': os.path.isfile(filepath),
            'is_dir': os.path.isdir(filepath),
            'extension': os.path.splitext(filepath)[1].lower(),
            'hash': file_hash,
            'mime_type': mime_type,
            'is_binary': is_binary,
            'permissions': oct(stat.st_mode)[-3:]
        }
    except Exception as e:
        logger.error(f"Dosya bilgisi alınamadı {filepath}: {e}")
        return None

def cleanup_old_files(directory: str, max_age_days: int = 30, dry_run: bool = False) -> Dict[str, int]:
    """Eski dosyaları temizle - Gelişmiş temizlik"""
    try:
        cutoff_time = datetime.now().timestamp() - (max_age_days * 24 * 3600)
        deleted_count = 0
        deleted_size = 0
        errors = 0
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    if os.path.getmtime(filepath) < cutoff_time:
                        if not dry_run:
                            file_size = os.path.getsize(filepath)
                            os.remove(filepath)
                            deleted_count += 1
                            deleted_size += file_size
                            logger.info(f"Eski dosya silindi: {filepath}")
                        else:
                            deleted_count += 1
                except Exception as e:
                    errors += 1
                    logger.warning(f"Dosya silinemedi {filepath}: {e}")
        
        result = {
            'deleted_files': deleted_count,
            'deleted_size': deleted_size,
            'deleted_size_str': get_file_size_str(deleted_size),
            'errors': errors
        }
        
        if not dry_run:
            logger.info(f"Temizlik tamamlandı: {deleted_count} dosya silindi")
        else:
            logger.info(f"Temizlik simülasyonu: {deleted_count} dosya silinecek")
        
        return result
        
    except Exception as e:
        logger.error(f"Temizlik hatası: {e}")
        return {'deleted_files': 0, 'deleted_size': 0, 'deleted_size_str': '0 B', 'errors': 1}

def validate_file_path(filepath: str) -> bool:
    """Dosya yolunun geçerli olup olmadığını kontrol et - Gelişmiş validasyon"""
    try:
        # Mutlak yol yap
        abs_path = os.path.abspath(filepath)
        
        # Geçersiz karakterleri kontrol et
        if any(char in abs_path for char in ['<', '>', ':', '"', '|', '?', '*']):
            return False
        
        # Çok uzun yol kontrolü
        if len(abs_path) > 260:  # Windows limit
            return False
        
        # Root directory kontrolü
        if os.name == 'nt':  # Windows
            if len(abs_path) < 3:  # C:\ minimum
                return False
        else:  # Unix/Linux
            if not abs_path.startswith('/'):
                return False
        
        return True
    except Exception:
        return False

def get_relative_path(base_path: str, full_path: str) -> str:
    """Tam yoldan göreceli yol al - Gelişmiş path handling"""
    try:
        return os.path.relpath(full_path, base_path)
    except ValueError:
        # Farklı drive'larda ise tam yol döndür
        return full_path
    except Exception:
        return full_path

def ensure_directory_exists(directory: str) -> bool:
    """Klasörün var olduğundan emin ol - Gelişmiş klasör oluşturma"""
    try:
        os.makedirs(directory, exist_ok=True)
        
        # Klasör yazma izni kontrolü
        test_file = os.path.join(directory, '.test_write')
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            return True
        except Exception:
            logger.warning(f"Klasör yazma izni yok: {directory}")
            return False
            
    except Exception as e:
        logger.error(f"Klasör oluşturulamadı {directory}: {e}")
        return False

def get_file_count(directory: str) -> Dict[str, int]:
    """Klasördeki dosya sayısını al - Detaylı analiz"""
    try:
        file_count = 0
        dir_count = 0
        total_size = 0
        file_types = {}
        
        for root, dirs, files in os.walk(directory):
            dir_count += len(dirs)
            for file in files:
                file_count += 1
                filepath = os.path.join(root, file)
                try:
                    total_size += os.path.getsize(filepath)
                    ext = os.path.splitext(file)[1].lower()
                    file_types[ext] = file_types.get(ext, 0) + 1
                except Exception:
                    continue
        
        return {
            'files': file_count,
            'directories': dir_count,
            'total_size': total_size,
            'total_size_str': get_file_size_str(total_size),
            'file_types': file_types
        }
    except Exception as e:
        logger.error(f"Dosya sayısı alınamadı {directory}: {e}")
        return {'files': 0, 'directories': 0, 'total_size': 0, 'total_size_str': '0 B', 'file_types': {}}

# YENİ GELİŞMİŞ FONKSİYONLAR

def create_archive(source_dir: str, output_path: str, archive_type: str = 'zip') -> bool:
    """Klasörü arşiv dosyasına sıkıştır"""
    try:
        if archive_type == 'zip':
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(source_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, source_dir)
                        zipf.write(file_path, arcname)
        
        elif archive_type == 'tar':
            with tarfile.open(output_path, 'w:gz') as tarf:
                tarf.add(source_dir, arcname=os.path.basename(source_dir))
        
        logger.info(f"Arşiv oluşturuldu: {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Arşiv oluşturulamadı: {e}")
        return False

def calculate_download_speed(start_time: float, downloaded_bytes: int) -> str:
    """İndirme hızını hesapla"""
    try:
        elapsed_time = time.time() - start_time
        if elapsed_time <= 0:
            return "0 B/s"
        
        speed_bps = downloaded_bytes / elapsed_time
        return f"{get_file_size_str(speed_bps)}/s"
    except Exception:
        return "0 B/s"

def estimate_remaining_time(start_time: float, downloaded_bytes: int, total_bytes: int) -> str:
    """Kalan süreyi tahmin et"""
    try:
        if downloaded_bytes <= 0 or total_bytes <= 0:
            return "Hesaplanamıyor"
        
        elapsed_time = time.time() - start_time
        if elapsed_time <= 0:
            return "Hesaplanamıyor"
        
        bytes_per_second = downloaded_bytes / elapsed_time
        remaining_bytes = total_bytes - downloaded_bytes
        remaining_seconds = remaining_bytes / bytes_per_second
        
        return format_duration(remaining_seconds)
    except Exception:
        return "Hesaplanamıyor"

def validate_url_safety(url: str) -> Dict[str, bool]:
    """URL güvenlik kontrolü"""
    try:
        parsed = urllib.parse.urlparse(url)
        
        # Şüpheli domain'ler
        suspicious_domains = [
            'localhost', '127.0.0.1', '0.0.0.0', '::1',
            'example.com', 'test.com', 'invalid.com'
        ]
        
        # Şüpheli port'lar
        suspicious_ports = [21, 22, 23, 25, 53, 80, 443, 8080, 8443]
        
        # Şüpheli scheme'ler
        suspicious_schemes = ['ftp', 'sftp', 'ssh', 'telnet', 'file']
        
        return {
            'is_safe': (
                parsed.scheme in ['http', 'https'] and
                parsed.port not in suspicious_ports and
                parsed.netloc not in suspicious_domains
            ),
            'has_suspicious_scheme': parsed.scheme in suspicious_schemes,
            'has_suspicious_port': parsed.port in suspicious_ports,
            'has_suspicious_domain': parsed.netloc in suspicious_domains
        }
    except Exception:
        return {'is_safe': False, 'has_suspicious_scheme': True, 'has_suspicious_port': True, 'has_suspicious_domain': True}

def create_download_report(download_info: Dict) -> str:
    """İndirme raporu oluştur"""
    try:
        report = f"""
📊 İndirme Raporu
{'='*50}

🌐 Site: {download_info.get('url', 'Bilinmiyor')}
📁 Klasör: {download_info.get('output_dir', 'Bilinmiyor')}
⏰ Başlangıç: {download_info.get('start_time', 'Bilinmiyor')}
⏰ Bitiş: {download_info.get('end_time', 'Devam ediyor')}

📊 İstatistikler:
   • Toplam dosya: {download_info.get('total_files', 0)}
   • İndirilen: {download_info.get('downloaded_files', 0)}
   • Hatalar: {download_info.get('errors', 0)}
   • Toplam boyut: {download_info.get('total_size', '0 B')}
   • İndirme hızı: {download_info.get('avg_speed', '0 B/s')}

⏱️ Süre: {download_info.get('duration', 'Hesaplanamıyor')}
✅ Durum: {'Tamamlandı' if download_info.get('completed', False) else 'Devam ediyor'}
"""
        return report
    except Exception as e:
        logger.error(f"Rapor oluşturulamadı: {e}")
        return "Rapor oluşturulamadı"

def cleanup_temp_files(temp_dir: str) -> bool:
    """Geçici dosyaları temizle"""
    try:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logger.info(f"Geçici dosyalar temizlendi: {temp_dir}")
            return True
        return True
    except Exception as e:
        logger.error(f"Geçici dosyalar temizlenemedi: {e}")
        return False

def get_system_info() -> Dict[str, str]:
    """Sistem bilgilerini al"""
    try:
        import platform
        import psutil
        
        return {
            'os': platform.system(),
            'os_version': platform.version(),
            'python_version': platform.python_version(),
            'cpu_count': str(psutil.cpu_count()),
            'memory_total': get_file_size_str(psutil.virtual_memory().total),
            'disk_free': get_file_size_str(psutil.disk_usage('/').free)
        }
    except ImportError:
        return {
            'os': 'Bilinmiyor',
            'os_version': 'Bilinmiyor',
            'python_version': platform.python_version(),
            'cpu_count': 'Bilinmiyor',
            'memory_total': 'Bilinmiyor',
            'disk_free': 'Bilinmiyor'
        }
    except Exception as e:
        logger.error(f"Sistem bilgisi alınamadı: {e}")
        return {'error': str(e)}

# Performans iyileştirmeleri için thread-safe queue
class ThreadSafeQueue:
    def __init__(self, maxsize: int = 1000):
        self.queue = queue.Queue(maxsize=maxsize)
        self.lock = threading.Lock()
    
    def put(self, item, block=True, timeout=None):
        """Queue'ya item ekle"""
        try:
            return self.queue.put(item, block=block, timeout=timeout)
        except queue.Full:
            logger.warning("Queue dolu, item eklenemedi")
            return False
    
    def get(self, block=True, timeout=None):
        """Queue'dan item al"""
        try:
            return self.queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return None
    
    def qsize(self):
        """Queue boyutunu al"""
        return self.queue.qsize()
    
    def empty(self):
        """Queue boş mu kontrol et"""
        return self.queue.empty()
    
    def full(self):
        """Queue dolu mu kontrol et"""
        return self.queue.full()

# Gelişmiş dosya işleme sınıfı
class AdvancedFileProcessor:
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.futures = []
    
    def process_file_async(self, filepath: str, processor_func):
        """Dosyayı asenkron olarak işle"""
        future = self.executor.submit(processor_func, filepath)
        self.futures.append(future)
        return future
    
    def wait_all(self):
        """Tüm işlemlerin tamamlanmasını bekle"""
        results = []
        for future in as_completed(self.futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                logger.error(f"Dosya işleme hatası: {e}")
                results.append(None)
        return results
    
    def shutdown(self):
        """Executor'ı kapat"""
        self.executor.shutdown(wait=True)

# Gelişmiş URL işleme sınıfı
class URLProcessor:
    def __init__(self):
        self.url_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'(\+90|0)?[0-9]{10}',
            'social_media': r'(facebook|twitter|instagram|linkedin|youtube)\.com',
            'file_extension': r'\.(html?|css|js|jpg|jpeg|png|gif|svg|ico|pdf|txt|zip|rar|doc|docx|xls|xlsx)$'
        }
    
    def extract_emails(self, text: str) -> List[str]:
        """Metinden email adreslerini çıkar"""
        return re.findall(self.url_patterns['email'], text)
    
    def extract_phones(self, text: str) -> List[str]:
        """Metinden telefon numaralarını çıkar"""
        return re.findall(self.url_patterns['phone'], text)
    
    def extract_social_media(self, text: str) -> List[str]:
        """Metinden sosyal medya linklerini çıkar"""
        return re.findall(self.url_patterns['social_media'], text)
    
    def is_downloadable_file(self, url: str) -> bool:
        """URL'nin indirilebilir dosya olup olmadığını kontrol et"""
        return bool(re.search(self.url_patterns['file_extension'], url, re.IGNORECASE))

# Gelişmiş güvenlik sınıfı
class SecurityManager:
    def __init__(self):
        self.threat_patterns = {
            'sql_injection': [
                r"(\b(union|select|insert|update|delete|drop|create|alter)\b)",
                r"(\b(exec|execute|script|javascript|vbscript)\b)",
                r"(--|/\*|\*/|xp_|sp_)"
            ],
            'xss': [
                r"(<script|javascript:|vbscript:|onload=|onerror=|onclick=)",
                r"(<iframe|<object|<embed|<form)",
                r"(alert\(|confirm\(|prompt\()"
            ],
            'path_traversal': [
                r"(\.\./|\.\.\\)",
                r"(/etc/|/var/|/tmp/|/home/)",
                r"(c:\\|d:\\)"
            ]
        }
    
    def scan_for_threats(self, content: str) -> Dict[str, List[str]]:
        """İçerikte tehdit türlerini tara"""
        threats = {}
        
        for threat_type, patterns in self.threat_patterns.items():
            threats[threat_type] = []
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    threats[threat_type].extend(matches)
        
        return threats
    
    def is_safe_content(self, content: str) -> bool:
        """İçeriğin güvenli olup olmadığını kontrol et"""
        threats = self.scan_for_threats(content)
        return not any(threats.values())

# Gelişmiş performans izleme sınıfı
class PerformanceMonitor:
    def __init__(self):
        self.start_time = time.time()
        self.operations = {}
        self.memory_usage = []
    
    def start_operation(self, operation_name: str):
        """Operasyon başlat"""
        self.operations[operation_name] = {
            'start': time.time(),
            'memory_start': self.get_memory_usage()
        }
    
    def end_operation(self, operation_name: str):
        """Operasyon bitir"""
        if operation_name in self.operations:
            end_time = time.time()
            memory_end = self.get_memory_usage()
            
            self.operations[operation_name].update({
                'end': end_time,
                'duration': end_time - self.operations[operation_name]['start'],
                'memory_end': memory_end,
                'memory_diff': memory_end - self.operations[operation_name]['memory_start']
            })
    
    def get_memory_usage(self) -> int:
        """Mevcut bellek kullanımını al"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss
        except:
            return 0
    
    def get_performance_report(self) -> str:
        """Performans raporu oluştur"""
        total_time = time.time() - self.start_time
        total_memory = self.get_memory_usage()
        
        report = f"""
🚀 Performans Raporu
{'='*50}

⏱️ Toplam süre: {format_duration(total_time)}
💾 Bellek kullanımı: {get_file_size_str(total_memory)}

📊 Operasyon Detayları:
"""
        
        for op_name, op_data in self.operations.items():
            if 'duration' in op_data:
                report += f"   • {op_name}: {format_duration(op_data['duration'])}\n"
                if 'memory_diff' in op_data:
                    report += f"     Bellek değişimi: {get_file_size_str(op_data['memory_diff'])}\n"
        
        return report

# Gelişmiş veri doğrulama sınıfı
class DataValidator:
    @staticmethod
    def validate_url(url: str) -> bool:
        """URL'nin geçerli olup olmadığını kontrol et"""
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def validate_file_path(filepath: str) -> bool:
        """Dosya yolunun geçerli olup olmadığını kontrol et"""
        try:
            # Mutlak yol yap
            abs_path = os.path.abspath(filepath)
            
            # Geçersiz karakterleri kontrol et
            if any(char in abs_path for char in ['<', '>', ':', '"', '|', '?', '*']):
                return False
            
            # Çok uzun yol kontrolü
            if len(abs_path) > 260:  # Windows limit
                return False
            
            return True
        except:
            return False
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Email adresinin geçerli olup olmadığını kontrol et"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_phone(phone: str) -> bool:
        """Telefon numarasının geçerli olup olmadığını kontrol et"""
        pattern = r'^(\+90|0)?[0-9]{10}$'
        return bool(re.match(pattern, phone))

# Gelişmiş dosya sıkıştırma sınıfı
class FileCompressor:
    def __init__(self, compression_level: int = 6):
        self.compression_level = compression_level
    
    def compress_file(self, input_path: str, output_path: str = None) -> str:
        """Dosyayı sıkıştır"""
        try:
            if output_path is None:
                output_path = input_path + '.gz'
            
            with open(input_path, 'rb') as f_in:
                with gzip.open(output_path, 'wb', compresslevel=self.compression_level) as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            logger.info(f"Dosya sıkıştırıldı: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Dosya sıkıştırılamadı: {e}")
            return None
    
    def decompress_file(self, input_path: str, output_path: str = None) -> str:
        """Sıkıştırılmış dosyayı aç"""
        try:
            if output_path is None:
                output_path = input_path.replace('.gz', '')
            
            with gzip.open(input_path, 'rb') as f_in:
                with open(output_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            logger.info(f"Dosya açıldı: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Dosya açılamadı: {e}")
            return None

# Gelişmiş cache yönetimi sınıfı
class CacheManager:
    def __init__(self, cache_dir: str = ".cache", max_size_mb: int = 100):
        self.cache_dir = cache_dir
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.cache_index_file = os.path.join(cache_dir, "index.json")
        self.cache_index = self.load_cache_index()
        
        os.makedirs(cache_dir, exist_ok=True)
    
    def load_cache_index(self) -> Dict:
        """Cache indeksini yükle"""
        try:
            if os.path.exists(self.cache_index_file):
                with open(self.cache_index_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except:
            pass
        return {}
    
    def save_cache_index(self):
        """Cache indeksini kaydet"""
        try:
            with open(self.cache_index_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache_index, f, indent=2, ensure_ascii=False)
        except:
            pass
    
    def get_cache_path(self, key: str) -> str:
        """Cache dosya yolunu al"""
        return os.path.join(self.cache_dir, f"{hashlib.md5(key.encode()).hexdigest()}")
    
    def set(self, key: str, data: bytes, ttl: int = 3600):
        """Cache'e veri ekle"""
        try:
            cache_path = self.get_cache_path(key)
            expiry_time = time.time() + ttl
            
            with open(cache_path, 'wb') as f:
                f.write(data)
            
            self.cache_index[key] = {
                'path': cache_path,
                'size': len(data),
                'expiry': expiry_time,
                'created': time.time()
            }
            
            self.save_cache_index()
            self.cleanup_cache()
            
        except Exception as e:
            logger.error(f"Cache'e veri eklenemedi: {e}")
    
    def get(self, key: str) -> Optional[bytes]:
        """Cache'den veri al"""
        try:
            if key not in self.cache_index:
                return None
            
            cache_info = self.cache_index[key]
            
            # TTL kontrolü
            if time.time() > cache_info['expiry']:
                self.delete(key)
                return None
            
            if os.path.exists(cache_info['path']):
                with open(cache_info['path'], 'rb') as f:
                    return f.read()
            else:
                self.delete(key)
                return None
                
        except Exception as e:
            logger.error(f"Cache'den veri alınamadı: {e}")
            return None
    
    def delete(self, key: str):
        """Cache'den veri sil"""
        try:
            if key in self.cache_index:
                cache_info = self.cache_index[key]
                if os.path.exists(cache_info['path']):
                    os.remove(cache_info['path'])
                del self.cache_index[key]
                self.save_cache_index()
        except:
            pass
    
    def cleanup_cache(self):
        """Cache'i temizle (boyut ve TTL kontrolü)"""
        try:
            current_time = time.time()
            total_size = 0
            
            # TTL kontrolü
            expired_keys = []
            for key, info in self.cache_index.items():
                if current_time > info['expiry']:
                    expired_keys.append(key)
                else:
                    total_size += info['size']
            
            # Süresi dolmuş dosyaları sil
            for key in expired_keys:
                self.delete(key)
            
            # Boyut kontrolü
            if total_size > self.max_size_bytes:
                # En eski dosyaları sil
                sorted_items = sorted(
                    self.cache_index.items(),
                    key=lambda x: x[1]['created']
                )
                
                for key, info in sorted_items:
                    if total_size <= self.max_size_bytes:
                        break
                    self.delete(key)
                    total_size -= info['size']
                    
        except Exception as e:
            logger.error(f"Cache temizleme hatası: {e}")
    
    def get_cache_stats(self) -> Dict:
        """Cache istatistiklerini al"""
        try:
            total_files = len(self.cache_index)
            total_size = sum(info['size'] for info in self.cache_index.values())
            
            return {
                'total_files': total_files,
                'total_size': total_size,
                'total_size_str': get_file_size_str(total_size),
                'max_size': self.max_size_bytes,
                'max_size_str': get_file_size_str(self.max_size_bytes),
                'usage_percent': (total_size / self.max_size_bytes) * 100
            }
        except:
            return {}

# Ana yardımcı fonksiyonlar için alias'lar
def log_info(message: str):
    """Bilgi mesajı logla"""
    logger.info(message)

def log_warning(message: str):
    """Uyarı mesajı logla"""
    logger.warning(message)

def log_error(message: str):
    """Hata mesajı logla"""
    logger.error(message)

def log_debug(message: str):
    """Debug mesajı logla"""
    logger.debug(message)

# Performans iyileştirmeleri için decorator'lar
def performance_monitor(func):
    """Fonksiyon performansını izle"""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        start_memory = get_memory_usage()
        
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            end_time = time.time()
            end_memory = get_memory_usage()
            
            duration = end_time - start_time
            memory_diff = end_memory - start_memory
            
            logger.debug(f"{func.__name__}: {format_duration(duration)}, Bellek: {get_file_size_str(memory_diff)}")
    
    return wrapper

def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    """Hata durumunda tekrar dene"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        logger.warning(f"{func.__name__} hatası (deneme {attempt + 1}/{max_retries}): {e}")
                        time.sleep(delay * (2 ** attempt))  # Exponential backoff
                    else:
                        logger.error(f"{func.__name__} son deneme başarısız: {e}")
            
            raise last_exception
        
        return wrapper
    return decorator

# Yardımcı fonksiyonlar
def get_memory_usage() -> int:
    """Mevcut bellek kullanımını al"""
    try:
        import psutil
        process = psutil.Process()
        return process.memory_info().rss
    except:
        return 0

def format_file_size(size_bytes: int) -> str:
    """Dosya boyutunu formatla (get_file_size_str için alias)"""
    return get_file_size_str(size_bytes)

def is_valid_file_path(filepath: str) -> bool:
    """Dosya yolunun geçerli olup olmadığını kontrol et (validate_file_path için alias)"""
    return DataValidator.validate_file_path(filepath)

def create_backup_file(filepath: str) -> str:
    """Dosya yedeği oluştur (create_backup_filename için alias)"""
    return create_backup_filename(filepath)

# Sürüm bilgisi
__version__ = "2.1.0"
__author__ = "Web Site Arşivleyici Pro Team"
__description__ = "Gelişmiş web site arşivleme ve yedekleme yardımcı fonksiyonları"

# Modül yüklendiğinde çalışacak kod
if __name__ == "__main__":
    # Test fonksiyonları
    print(f"🌐 Web Site Arşivleyici Pro Utils v{__version__}")
    print("=" * 50)
    
    # Temel fonksiyonları test et
    test_url = "https://example.com/test.html"
    print(f"URL doğrulama: {is_valid_url(test_url)}")
    print(f"Domain: {get_domain_from_url(test_url)}")
    print(f"Dosya uzantısı: {get_file_extension_from_url(test_url)}")
    
    # Güvenlik testi
    security = SecurityManager()
    test_content = "<script>alert('test')</script>"
    print(f"Güvenli içerik: {security.is_safe_content(test_content)}")
    
    # Performans izleme testi
    monitor = PerformanceMonitor()
    monitor.start_operation("test_operation")
    time.sleep(0.1)
    monitor.end_operation("test_operation")
    print("Performans izleme testi tamamlandı")
    
    print("\n✅ Tüm testler başarıyla tamamlandı!") 