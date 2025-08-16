import os
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import mimetypes
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from datetime import datetime
import re
import ssl
import socket
from urllib3.exceptions import InsecureRequestWarning
import warnings

# Güvenlik uyarılarını kapat
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

class SiteCrawler:
    def __init__(self, log_callback=None, progress_callback=None):
        self.visited = set()
        self.downloaded_files = 0
        self.total_files = 0
        self.log_callback = log_callback or print
        self.progress_callback = progress_callback
        self.stop_crawling = False
        self.errors = []
        self.warnings = []
        self.start_time = time.time()
        self.download_stats = {
            'total_size': 0,
            'html_files': 0,
            'css_files': 0,
            'js_files': 0,
            'image_files': 0,
            'other_files': 0
        }
        
    def log(self, message):
        """Log mesajı gönder"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        if self.log_callback:
            self.log_callback(formatted_message)
    
    def log_error(self, message):
        """Hata mesajı logla"""
        self.errors.append(message)
        self.log(f"❌ {message}")
    
    def log_warning(self, message):
        """Uyarı mesajı logla"""
        self.warnings.append(message)
        self.log(f"⚠️ {message}")
    
    def update_progress(self, current, total):
        """İlerleme durumunu güncelle"""
        if self.progress_callback:
            try:
                percentage = (current / total) * 100 if total > 0 else 0
                # GUI thread'inde güvenli güncelleme
                if hasattr(self.progress_callback, 'set'):
                    self.progress_callback.set(percentage)
                elif callable(self.progress_callback):
                    self.progress_callback(percentage)
            except Exception as e:
                self.log(f"Progress güncelleme hatası: {str(e)}")
    
    def get_file_extension(self, url, content_type=None):
        """Dosya uzantısını belirle"""
        parsed = urlparse(url)
        path = parsed.path
        
        # URL'den uzantı al
        if '.' in path:
            ext = path.split('.')[-1].lower()
            if ext in ['html', 'htm', 'css', 'js', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'ico', 'pdf', 'txt', 'xml', 'json']:
                return ext
        
        # Content-Type'dan uzantı al
        if content_type:
            ext = mimetypes.guess_extension(content_type)
            if ext:
                return ext.lstrip('.')
        
        # Varsayılan HTML
        return 'html'
    
    def validate_url_security(self, url):
        """URL güvenlik kontrolü"""
        try:
            parsed = urlparse(url)
            
            # Şüpheli scheme'ler
            if parsed.scheme not in ['http', 'https']:
                return False, "Güvensiz protokol"
            
            # Şüpheli domain'ler
            suspicious_domains = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
            if parsed.netloc in suspicious_domains:
                return False, "Şüpheli domain"
            
            # Port kontrolü
            if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
                return False, "Şüpheli port"
            
            return True, "Güvenli"
            
        except Exception as e:
            return False, f"URL parse hatası: {e}"
    
    def get_file_size_str(self, size_bytes):
        """Byte cinsinden boyutu okunabilir formata çevir"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"
    
    def save_file(self, output_dir, url, content, is_binary=False):
        """Dosyayı kaydet"""
        try:
            parsed_url = urlparse(url)
            path = parsed_url.path
            
            # Ana sayfa için index.html
            if path.endswith('/') or not path:
                path += 'index.html'
            
            # Dosya uzantısını belirle
            if not os.path.splitext(path)[1]:
                ext = self.get_file_extension(url)
                if ext != 'html':
                    path += f'.{ext}'
            
            # Dosya yolu oluştur
            filename = os.path.join(output_dir, parsed_url.netloc, path.lstrip('/'))
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            # Dosyayı kaydet
            mode = "wb" if is_binary else "w"
            encoding = None if is_binary else "utf-8"
            
            with open(filename, mode, encoding=encoding) as f:
                if is_binary:
                    f.write(content)
                else:
                    f.write(content)
            
            # İstatistikleri güncelle
            file_size = len(content) if isinstance(content, bytes) else len(content.encode('utf-8'))
            self.download_stats['total_size'] += file_size
            
            # Dosya türüne göre sayacı güncelle
            ext = self.get_file_extension(url)
            if ext in ['html', 'htm']:
                self.download_stats['html_files'] += 1
            elif ext == 'css':
                self.download_stats['css_files'] += 1
            elif ext == 'js':
                self.download_stats['js_files'] += 1
            elif ext in ['jpg', 'jpeg', 'png', 'gif', 'svg', 'ico']:
                self.download_stats['image_files'] += 1
            else:
                self.download_stats['other_files'] += 1
            
            self.downloaded_files += 1
            self.log(f"✅ Kaydedildi: {os.path.basename(filename)} ({self.get_file_size_str(file_size)})")
            
            # İlerleme güncelle - her dosyada
            self.update_progress(self.downloaded_files, self.total_files)
            
        except Exception as e:
            self.log_error(f"Dosya kaydetme hatası: {str(e)}")
    
    def download_resource(self, url, output_dir, base_url):
        """Kaynak dosyayı indir (CSS, JS, resim vb.)"""
        try:
            if url in self.visited:
                return
            
            self.visited.add(url)
            
            # Güvenlik kontrolü
            is_safe, reason = self.validate_url_security(url)
            if not is_safe:
                self.log_warning(f"Güvensiz URL atlandı: {url} - {reason}")
                return
            
            # Headers ekle
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Referer': base_url,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'tr-TR,tr;q=0.9,en;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # SSL doğrulamasını kapat (geliştirme için)
            response = requests.get(url, headers=headers, timeout=30, verify=False, allow_redirects=True)
            response.raise_for_status()
            
            # Content-Type kontrolü
            content_type = response.headers.get('content-type', '').split(';')[0]
            
            # Binary dosya kontrolü
            is_binary = not content_type.startswith('text/')
            
            # Dosyayı kaydet
            self.save_file(output_dir, url, response.content if is_binary else response.text, is_binary)
            
        except requests.exceptions.RequestException as e:
            self.log_warning(f"Kaynak indirme hatası ({url}): {str(e)}")
        except Exception as e:
            self.log_error(f"Beklenmeyen hata ({url}): {str(e)}")
    
    def get_site_info(self, url):
        """Site hakkında bilgi al"""
        try:
            parsed = urlparse(url)
            
            # SSL sertifika bilgisi
            ssl_info = {}
            try:
                context = ssl.create_default_context()
                with socket.create_connection((parsed.netloc, 443 if parsed.scheme == 'https' else 80), timeout=10) as sock:
                    if parsed.scheme == 'https':
                        with context.wrap_socket(sock, server_hostname=parsed.netloc) as ssock:
                            cert = ssock.getpeercert()
                            ssl_info = {
                                'issuer': dict(x[0] for x in cert['issuer']),
                                'subject': dict(x[0] for x in cert['subject']),
                                'expiry': cert['notAfter']
                            }
            except:
                pass
            
            return {
                'domain': parsed.netloc,
                'scheme': parsed.scheme,
                'path': parsed.path,
                'ssl_info': ssl_info,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            self.log_error(f"Site bilgisi alınamadı: {e}")
            return {}
    
    def create_site_report(self):
        """Site indirme raporu oluştur"""
        end_time = time.time()
        duration = end_time - self.start_time
        
        report = {
            'summary': {
                'total_files': self.downloaded_files,
                'total_size': self.download_stats['total_size'],
                'total_size_str': self.get_file_size_str(self.download_stats['total_size']),
                'duration': duration,
                'duration_str': f"{duration:.1f}s",
                'errors': len(self.errors),
                'warnings': len(self.warnings)
            },
            'file_types': self.download_stats,
            'errors': self.errors,
            'warnings': self.warnings,
            'timestamp': datetime.now().isoformat()
        }
        
        return report
    
    def save_site_report(self, output_dir, report):
        """Site raporunu kaydet"""
        try:
            report_file = os.path.join(output_dir, 'site_report.json')
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.log(f"📊 Site raporu kaydedildi: {report_file}")
        except Exception as e:
            self.log_error(f"Rapor kaydedilemedi: {e}")
    
    def crawl_site(self, url, output_dir, max_depth=2, delay=2):
        """Site'i crawl et"""
        try:
            self.log(f"🚀 Site arşivleme başlatılıyor: {url}")
            self.log(f"📁 Çıktı klasörü: {output_dir}")
            self.log(f"🔍 Maksimum derinlik: {max_depth}")
            self.log(f"⏱️ Gecikme: {delay}s")
            
            # Site bilgilerini al
            site_info = self.get_site_info(url)
            self.log(f"🌐 Domain: {site_info.get('domain', 'Bilinmiyor')}")
            
            # Chrome options
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
            
            # WebDriver başlat
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(30)
            
            try:
                # Ana sayfayı yükle
                self.log("📄 Ana sayfa yükleniyor...")
                driver.get(url)
                time.sleep(delay)
                
                # Sayfa yüklenmesini bekle
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                
                # HTML içeriği al
                page_html = driver.page_source
                
                # Ana sayfayı kaydet
                self.save_file(output_dir, url, page_html)
                
                # BeautifulSoup ile parse et
                soup = BeautifulSoup(page_html, 'html.parser')
                
                # Kaynak dosyaları bul
                resources = []
                
                # CSS dosyaları
                for link in soup.find_all("link", rel="stylesheet"):
                    href = link.get("href")
                    if href:
                        full_url = urljoin(url, href)
                        resources.append(full_url)
                
                # JavaScript dosyaları
                for script in soup.find_all("script", src=True):
                    src = script.get("src")
                    if src:
                        full_url = urljoin(url, src)
                        resources.append(full_url)
                
                # Resimler
                for img in soup.find_all("img", src=True):
                    src = img.get("src")
                    if src:
                        full_url = urljoin(url, src)
                        resources.append(full_url)
                
                # Favicon
                for link in soup.find_all("link", rel="icon"):
                    href = link.get("href")
                    if href:
                        full_url = urljoin(url, href)
                        resources.append(full_url)
                
                # Toplam dosya sayısını hesapla
                self.total_files = 1 + len(resources)  # Ana sayfa + kaynaklar
                
                # İlk progress güncelleme
                self.update_progress(0, self.total_files)
                
                # Linkleri bul ve derinlik taraması yap
                if max_depth > 1:
                    self.log(f"🔗 Linkler taranıyor (derinlik: {max_depth})...")
                    links = soup.find_all("a", href=True)
                    internal_links = []
                    
                    for link in links:
                        href = link.get("href")
                        if href:
                            full_url = urljoin(url, href)
                            # Sadece aynı domain'den linkleri takip et
                            if urlparse(full_url).netloc == urlparse(url).netloc:
                                internal_links.append(full_url)
                    
                    # Benzersiz linkleri al
                    unique_links = list(set(internal_links))
                    self.log(f"🔍 {len(unique_links)} benzersiz link bulundu")
                    
                    # Derinlik taraması için toplam dosya sayısını güncelle
                    max_pages = min(20, len(unique_links))
                    self.total_files += max_pages
                    
                    # Progress'i yeniden hesapla
                    self.update_progress(self.downloaded_files, self.total_files)
                    
                    # Derinlik taraması
                    for i, link_url in enumerate(unique_links[:20]):  # Maksimum 20 sayfa
                        if self.stop_crawling:
                            break
                        
                        if link_url not in self.visited:
                            try:
                                self.log(f"📄 Sayfa {i+1}/{max_pages}: {link_url}")
                                driver.get(link_url)
                                time.sleep(delay)
                                
                                page_html = driver.page_source
                                self.save_file(output_dir, link_url, page_html)
                                
                                # Progress güncelle
                                self.update_progress(self.downloaded_files, self.total_files)
                                
                            except Exception as e:
                                self.log_warning(f"Sayfa indirme hatası ({link_url}): {str(e)}")
                
                # Kaynak dosyaları indir
                if resources:
                    self.log(f"📦 {len(resources)} kaynak dosya bulundu, indiriliyor...")
                    
                    with ThreadPoolExecutor(max_workers=5) as executor:
                        futures = []
                        for resource_url in resources:
                            if not self.stop_crawling:
                                future = executor.submit(self.download_resource, resource_url, output_dir, url)
                                futures.append(future)
                                time.sleep(0.1)  # Küçük gecikme
                        
                        # Tamamlanan işleri bekle
                        for future in as_completed(futures):
                            if self.stop_crawling:
                                break
                            try:
                                future.result()
                            except Exception as e:
                                self.log_error(f"Kaynak indirme hatası: {str(e)}")
                
            finally:
                driver.quit()
            
            # Final ilerleme güncelle
            self.update_progress(self.downloaded_files, self.total_files)
            
            # Site raporu oluştur ve kaydet
            report = self.create_site_report()
            self.save_site_report(output_dir, report)
            
            self.log(f"✅ Arşivleme tamamlandı!")
            self.log(f"📊 Toplam indirilen dosya: {self.downloaded_files}")
            self.log(f"💾 Toplam boyut: {self.get_file_size_str(self.download_stats['total_size'])}")
            self.log(f"⏱️ Toplam süre: {report['summary']['duration_str']}")
            
            if self.errors:
                self.log(f"❌ Hatalar: {len(self.errors)}")
            if self.warnings:
                self.log(f"⚠️ Uyarılar: {len(self.warnings)}")
            
        except Exception as e:
            self.log_error(f"Kritik hata: {str(e)}")
            if 'driver' in locals():
                driver.quit()
            raise e
    
    def stop(self):
        """Crawling'i durdur"""
        self.stop_crawling = True
        self.log("⏹️ Arşivleme durduruldu")

# Eski fonksiyon adını koru (geriye uyumluluk için)
def crawl_site(url, output_dir, max_depth=2, delay=2, log_callback=None, progress_callback=None):
    """Site crawling fonksiyonu (geriye uyumluluk için)"""
    crawler = SiteCrawler(log_callback, progress_callback)
    return crawler.crawl_site(url, output_dir, max_depth, delay)
