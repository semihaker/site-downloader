#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Site Arşivleyici Pro - Konfigürasyon Dosyası
Versiyon: 2.1.0
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional

class Config:
    def __init__(self):
        self.config_file = 'config.json'
        self.default_config = {
            'app_name': 'Web Site Arşivleyici Pro',
            'version': '2.1.0',
            'author': 'Web Site Arşivleyici Pro Team',
            'description': 'Profesyonel web site arşivleme ve yedekleme çözümü',
            
            # GUI Ayarları
            'gui': {
                'theme': 'dark',
                'window_size': '900x800',
                'min_window_size': '800x600',
                'center_window': True,
                'resizable': True,
                'auto_save_settings': True,
                'show_tooltips': True,
                'language': 'tr',
                'font_size': 10,
                'animation_enabled': True
            },
            
            # Varsayılan İndirme Ayarları
            'download': {
                'default_depth': 2,
                'default_delay': 2,
                'default_file_types': 'Tümü',
                'max_pages': 20,
                'max_file_size': 100,  # MB
                'timeout': 30,  # saniye
                'retry_count': 3,
                'follow_redirects': True,
                'respect_robots_txt': True,
                'download_external_resources': False,
                'create_sitemap': True,
                'compress_downloads': False
            },
            
            # Performans Ayarları
            'performance': {
                'max_threads': 5,
                'chunk_size': 8192,  # bytes
                'buffer_size': 1024 * 1024,  # 1MB
                'memory_limit': 512,  # MB
                'enable_caching': True,
                'cache_size': 100,  # MB
                'cache_ttl': 3600,  # saniye
                'enable_compression': False,
                'compression_level': 6
            },
            
            # Desteklenen Dosya Türleri
            'supported_extensions': [
                'html', 'htm', 'css', 'js', 'json', 'xml',
                'jpg', 'jpeg', 'png', 'gif', 'svg', 'ico', 'webp',
                'pdf', 'txt', 'md', 'csv',
                'woff', 'woff2', 'ttf', 'eot',
                'mp3', 'mp4', 'avi', 'mov', 'wmv',
                'zip', 'rar', '7z', 'tar', 'gz',
                'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'
            ],
            
            # User Agent Listesi
            'user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            ],
            
            # Chrome Ayarları
            'chrome': {
                'headless': True,
                'no_sandbox': True,
                'disable_dev_shm_usage': True,
                'disable_gpu': True,
                'window_size': '1920,1080',
                'page_load_timeout': 60,
                'implicit_wait': 10,
                'disable_images': False,
                'disable_javascript': False,
                'disable_css': False,
                'user_data_dir': None,
                'profile_directory': None
            },
            
            # Log Ayarları
            'logging': {
                'level': 'INFO',
                'max_log_size': 10,  # MB
                'backup_count': 5,
                'format': '[%(asctime)s] %(levelname)s: %(message)s',
                'date_format': '%Y-%m-%d %H:%M:%S',
                'log_to_file': True,
                'log_to_console': True,
                'log_directory': 'logs',
                'enable_debug_logging': False
            },
            
            # Güvenlik Ayarları
            'security': {
                'max_url_length': 2048,
                'allowed_protocols': ['http', 'https'],
                'blocked_domains': [],
                'rate_limit': {
                    'requests_per_second': 2,
                    'max_concurrent': 5
                },
                'enable_ssl_verification': True,
                'block_suspicious_urls': True,
                'max_file_size_limit': True,
                'scan_for_threats': True,
                'allowed_file_types': ['html', 'css', 'js', 'jpg', 'png', 'gif', 'pdf'],
                'blocked_file_types': ['exe', 'bat', 'cmd', 'scr', 'pif', 'com']
            },
            
            # Gelişmiş Ayarlar
            'advanced': {
                'enable_metadata_extraction': True,
                'create_backup_before_download': True,
                'enable_file_validation': True,
                'enable_duplicate_detection': True,
                'enable_progress_tracking': True,
                'enable_error_recovery': True,
                'max_retry_attempts': 3,
                'retry_delay': 5,  # saniye
                'enable_auto_cleanup': True,
                'cleanup_old_files_after_days': 30
            },
            
            # Bildirim Ayarları
            'notifications': {
                'enable_desktop_notifications': True,
                'enable_sound_notifications': False,
                'notify_on_completion': True,
                'notify_on_error': True,
                'notify_on_warning': False,
                'notification_duration': 5  # saniye
            },
            
            # Ağ Ayarları
            'network': {
                'connection_timeout': 30,
                'read_timeout': 60,
                'max_redirects': 5,
                'enable_proxy': False,
                'proxy_settings': {
                    'http': None,
                    'https': None,
                    'username': None,
                    'password': None
                },
                'enable_tor': False,
                'tor_settings': {
                    'socks_host': '127.0.0.1',
                    'socks_port': 9050
                }
            },
            
            # Veri Tabanı Ayarları
            'database': {
                'enable_sqlite': True,
                'sqlite_file': 'downloads.db',
                'enable_history_tracking': True,
                'max_history_entries': 1000,
                'auto_cleanup_history': True,
                'history_cleanup_days': 90
            },
            
            # Yedekleme Ayarları
            'backup': {
                'enable_auto_backup': True,
                'backup_interval_hours': 24,
                'max_backup_files': 10,
                'backup_directory': 'backups',
                'compress_backups': True,
                'backup_compression_level': 6
            }
        }
        
        self.config = self.load_config()
        self.validate_config()
    
    def load_config(self):
        """Konfigürasyon dosyasını yükle"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    # Varsayılan ayarlarla birleştir
                    return self.merge_configs(self.default_config, loaded_config)
            else:
                # Varsayılan ayarları kaydet
                self.save_config(self.default_config)
                return self.default_config
        except Exception as e:
            print(f"Konfigürasyon yüklenirken hata: {e}")
            return self.default_config
    
    def merge_configs(self, default, loaded):
        """Varsayılan ve yüklenen konfigürasyonları birleştir"""
        merged = default.copy()
        
        def deep_merge(d1, d2):
            for key, value in d2.items():
                if key in d1 and isinstance(d1[key], dict) and isinstance(value, dict):
                    deep_merge(d1[key], value)
                else:
                    d1[key] = value
        
        deep_merge(merged, loaded)
        return merged
    
    def validate_config(self):
        """Konfigürasyon değerlerini doğrula"""
        try:
            # Temel doğrulamalar
            if self.config['download']['default_depth'] < 1:
                self.config['download']['default_depth'] = 1
            elif self.config['download']['default_depth'] > 10:
                self.config['download']['default_depth'] = 10
            
            if self.config['download']['default_delay'] < 0:
                self.config['download']['default_delay'] = 0
            elif self.config['download']['default_delay'] > 60:
                self.config['download']['default_delay'] = 60
            
            if self.config['performance']['max_threads'] < 1:
                self.config['performance']['max_threads'] = 1
            elif self.config['performance']['max_threads'] > 20:
                self.config['performance']['max_threads'] = 20
            
            # Güvenlik doğrulamaları
            if not isinstance(self.config['security']['blocked_domains'], list):
                self.config['security']['blocked_domains'] = []
            
            # Log dizinini oluştur
            log_dir = self.config['logging']['log_directory']
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            # Yedekleme dizinini oluştur
            backup_dir = self.config['backup']['backup_directory']
            if backup_dir and not os.path.exists(backup_dir):
                os.makedirs(backup_dir, exist_ok=True)
                
        except Exception as e:
            print(f"Konfigürasyon doğrulama hatası: {e}")
    
    def save_config(self, config=None):
        """Konfigürasyon dosyasını kaydet"""
        if config is None:
            config = self.config
        
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Konfigürasyon kaydedilirken hata: {e}")
    
    def get(self, key, default=None):
        """Konfigürasyon değerini al"""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key, value):
        """Konfigürasyon değerini ayarla"""
        keys = key.split('.')
        config = self.config
        
        # Son anahtara kadar git
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Değeri ayarla
        config[keys[-1]] = value
        self.save_config()
        self.validate_config()
    
    def update(self, updates):
        """Birden fazla konfigürasyon değerini güncelle"""
        for key, value in updates.items():
            self.set(key, value)
    
    def reset_to_defaults(self):
        """Varsayılan ayarlara sıfırla"""
        self.config = self.default_config.copy()
        self.save_config()
        self.validate_config()
    
    def get_download_config(self):
        """İndirme konfigürasyonunu al"""
        return self.get('download', {})
    
    def get_chrome_config(self):
        """Chrome konfigürasyonunu al"""
        return self.get('chrome', {})
    
    def get_performance_config(self):
        """Performans konfigürasyonunu al"""
        return self.get('performance', {})
    
    def get_supported_extensions(self):
        """Desteklenen dosya uzantılarını al"""
        return self.get('supported_extensions', [])
    
    def get_user_agents(self):
        """User agent listesini al"""
        return self.get('user_agents', [])
    
    def get_security_config(self):
        """Güvenlik konfigürasyonunu al"""
        return self.get('security', {})
    
    def get_advanced_config(self):
        """Gelişmiş konfigürasyonu al"""
        return self.get('advanced', {})
    
    def get_notification_config(self):
        """Bildirim konfigürasyonunu al"""
        return self.get('notifications', {})
    
    def get_network_config(self):
        """Ağ konfigürasyonunu al"""
        return self.get('network', {})
    
    def get_database_config(self):
        """Veri tabanı konfigürasyonunu al"""
        return self.get('database', {})
    
    def get_backup_config(self):
        """Yedekleme konfigürasyonunu al"""
        return self.get('backup', {})
    
    def is_extension_supported(self, extension: str) -> bool:
        """Dosya uzantısının desteklenip desteklenmediğini kontrol et"""
        return extension.lower() in [ext.lower() for ext in self.get_supported_extensions()]
    
    def is_domain_blocked(self, domain: str) -> bool:
        """Domain'in engellenip engellenmediğini kontrol et"""
        blocked_domains = self.get('security.blocked_domains', [])
        return domain.lower() in [d.lower() for d in blocked_domains]
    
    def is_file_type_allowed(self, file_type: str) -> bool:
        """Dosya türünün izin verilip verilmediğini kontrol et"""
        allowed_types = self.get('security.allowed_file_types', [])
        blocked_types = self.get('security.blocked_file_types', [])
        
        if file_type.lower() in [t.lower() for t in blocked_types]:
            return False
        
        if not allowed_types or file_type.lower() in [t.lower() for t in allowed_types]:
            return True
        
        return False
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Konfigürasyon özetini al"""
        return {
            'app_info': {
                'name': self.get('app_name'),
                'version': self.get('version'),
                'author': self.get('author')
            },
            'download_settings': self.get_download_config(),
            'performance_settings': self.get_performance_config(),
            'security_settings': self.get_security_config(),
            'supported_extensions_count': len(self.get_supported_extensions()),
            'user_agents_count': len(self.get_user_agents())
        }
    
    def export_config(self, filepath: str) -> bool:
        """Konfigürasyonu dışa aktar"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Konfigürasyon dışa aktarma hatası: {e}")
            return False
    
    def import_config(self, filepath: str) -> bool:
        """Konfigürasyonu içe aktar"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
            
            # Mevcut konfigürasyonla birleştir
            self.config = self.merge_configs(self.default_config, imported_config)
            self.save_config()
            self.validate_config()
            return True
        except Exception as e:
            print(f"Konfigürasyon içe aktarma hatası: {e}")
            return False

# Global config instance
config = Config()

# Kolay erişim fonksiyonları
def get_config(key, default=None):
    return config.get(key, default)

def set_config(key, value):
    config.set(key, value)

def update_config(updates):
    config.update(updates)

def is_extension_supported(extension: str) -> bool:
    return config.is_extension_supported(extension)

def is_domain_blocked(domain: str) -> bool:
    return config.is_domain_blocked(domain)

def is_file_type_allowed(file_type: str) -> bool:
    return config.is_file_type_allowed(file_type)

def get_config_summary() -> Dict[str, Any]:
    return config.get_config_summary()

def export_config(filepath: str) -> bool:
    return config.export_config(filepath)

def import_config(filepath: str) -> bool:
    return config.import_config(filepath)
