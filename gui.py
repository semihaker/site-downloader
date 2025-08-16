import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
from datetime import datetime
import json
import webbrowser
from crawler import crawl_site

class ModernSiteDownloader:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🌐 Web Site Arşivleyici Pro v2.0")
        self.root.geometry("900x800")
        self.root.configure(bg="#0f1419")
        self.root.resizable(True, True)
        
        # Özel renkler
        self.colors = {
            'bg_dark': '#0f1419',
            'bg_medium': '#1a1f2e',
            'bg_light': '#2d3748',
            'accent_blue': '#3b82f6',
            'accent_green': '#10b981',
            'accent_red': '#ef4444',
            'accent_yellow': '#f59e0b',
            'text_light': '#f8fafc',
            'text_gray': '#94a3b8'
        }
        
        # Ana stil ayarları
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Progress bar style'ı - basit ve çalışan
        self.style.configure("Custom.Horizontal.TProgressbar",
                           troughcolor='#2d3748',
                           background='#10b981',
                           bordercolor='#1a1f2e')
        
        self.output_folder = ""
        self.is_downloading = False
        self.crawler = None
        self.download_history = []
        self.settings = self.load_settings()
        
        self.setup_ui()
        self.center_window()
        self.load_download_history()
        
    def load_settings(self):
        """Ayarları yükle"""
        try:
            with open('settings.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {
                'default_depth': '2',
                'default_delay': '2',
                'default_file_types': 'Tümü',
                'theme': 'dark',
                'auto_save': True
            }
    
    def save_settings(self):
        """Ayarları kaydet"""
        try:
            with open('settings.json', 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=2, ensure_ascii=False)
        except:
            pass
        
    def center_window(self):
        """Pencereyi ekranın ortasına yerleştir"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_ui(self):
        """Ana kullanıcı arayüzünü oluştur"""
        # Ana başlık - Gradient efekti
        title_frame = tk.Frame(self.root, bg=self.colors['bg_medium'], height=100)
        title_frame.pack(fill="x", padx=0, pady=0)
        title_frame.pack_propagate(False)
        
        # Başlık ve alt başlık
        title_label = tk.Label(
            title_frame, 
            text="🌐 Web Site Arşivleyici Pro", 
            font=("Segoe UI", 24, "bold"), 
            fg=self.colors['text_light'], 
            bg=self.colors['bg_medium']
        )
        title_label.pack(pady=(15, 5))
        
        subtitle_label = tk.Label(
            title_frame,
            text="🚀 Profesyonel Web Arşivleme ve Yedekleme Çözümü",
            font=("Segoe UI", 12),
            fg=self.colors['text_gray'],
            bg=self.colors['bg_medium']
        )
        subtitle_label.pack()
        
        # Ana içerik alanı
        main_frame = tk.Frame(self.root, bg=self.colors['bg_dark'])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # URL giriş alanı - Daha büyük ve şık
        url_frame = tk.LabelFrame(main_frame, text="🎯 Site Bilgileri", font=("Segoe UI", 14, "bold"), 
                                 bg=self.colors['bg_medium'], fg=self.colors['text_light'], relief="groove", bd=2)
        url_frame.pack(fill="x", pady=(0, 20))
        
        tk.Label(url_frame, text="🌍 Site URL:", font=("Segoe UI", 12), bg=self.colors['bg_medium'], fg=self.colors['text_light']).pack(anchor="w", padx=15, pady=(15, 8))
        self.url_entry = tk.Entry(url_frame, font=("Segoe UI", 13), relief="solid", bd=1, bg=self.colors['bg_light'], fg=self.colors['text_light'])
        self.url_entry.pack(fill="x", padx=15, pady=(0, 15))
        self.url_entry.insert(0, "https://")
        
        # Ayarlar çerçevesi - Daha detaylı
        settings_frame = tk.LabelFrame(main_frame, text="⚙️ İndirme Ayarları", font=("Segoe UI", 14, "bold"),
                                     bg=self.colors['bg_medium'], fg=self.colors['text_light'], relief="groove", bd=2)
        settings_frame.pack(fill="x", pady=(0, 20))
        
        # Ayarlar grid - 2 sütun
        settings_grid = tk.Frame(settings_frame, bg=self.colors['bg_medium'])
        settings_grid.pack(fill="x", padx=15, pady=15)
        
        # Sol sütun
        left_column = tk.Frame(settings_grid, bg=self.colors['bg_medium'])
        left_column.pack(side="left", fill="x", expand=True)
        
        # Tarama derinliği
        tk.Label(left_column, text="🔍 Tarama Derinliği:", font=("Segoe UI", 11), bg=self.colors['bg_medium'], fg=self.colors['text_light']).pack(anchor="w", pady=5)
        self.depth_var = tk.StringVar(value=self.settings.get('default_depth', '2'))
        depth_combo = ttk.Combobox(left_column, textvariable=self.depth_var, values=["1", "2", "3", "4", "5"], 
                                  state="readonly", width=12, font=("Segoe UI", 10))
        depth_combo.pack(anchor="w", pady=(0, 10))
        
        # Gecikme süresi
        tk.Label(left_column, text="⏱️ Sayfa Gecikmesi (sn):", font=("Segoe UI", 11), bg=self.colors['bg_medium'], fg=self.colors['text_light']).pack(anchor="w", pady=5)
        self.delay_var = tk.StringVar(value=self.settings.get('default_delay', '2'))
        delay_combo = ttk.Combobox(left_column, textvariable=self.delay_var, values=["1", "2", "3", "5", "10"], 
                                  state="readonly", width=12, font=("Segoe UI", 10))
        delay_combo.pack(anchor="w", pady=(0, 10))
        
        # Sağ sütun
        right_column = tk.Frame(settings_grid, bg=self.colors['bg_medium'])
        right_column.pack(side="right", fill="x", expand=True)
        
        # Dosya türleri
        tk.Label(right_column, text="📁 İndirilecek Dosyalar:", font=("Segoe UI", 11), bg=self.colors['bg_medium'], fg=self.colors['text_light']).pack(anchor="w", pady=5)
        self.file_types_var = tk.StringVar(value=self.settings.get('default_file_types', 'Tümü'))
        file_types_combo = ttk.Combobox(right_column, textvariable=self.file_types_var, 
                                       values=["Tümü", "Sadece HTML", "HTML + CSS + JS", "Sadece Resimler"], 
                                       state="readonly", width=18, font=("Segoe UI", 10))
        file_types_combo.pack(anchor="w", pady=(0, 10))
        
        # Maksimum sayfa sayısı
        tk.Label(right_column, text="📊 Maksimum Sayfa:", font=("Segoe UI", 11), bg=self.colors['bg_medium'], fg=self.colors['text_light']).pack(anchor="w", pady=5)
        self.max_pages_var = tk.StringVar(value="20")
        max_pages_combo = ttk.Combobox(right_column, textvariable=self.max_pages_var, 
                                      values=["10", "20", "50", "100", "Sınırsız"], 
                                      state="readonly", width=18, font=("Segoe UI", 10))
        max_pages_combo.pack(anchor="w", pady=(0, 10))
        
        # Klasör seçimi - Daha şık
        folder_frame = tk.LabelFrame(main_frame, text="💾 Kayıt Konumu", font=("Segoe UI", 14, "bold"),
                                   bg=self.colors['bg_medium'], fg=self.colors['text_light'], relief="groove", bd=2)
        folder_frame.pack(fill="x", pady=(0, 20))
        
        folder_select_frame = tk.Frame(folder_frame, bg=self.colors['bg_medium'])
        folder_select_frame.pack(fill="x", padx=15, pady=15)
        
        self.folder_label = tk.Label(folder_select_frame, text="📂 Henüz klasör seçilmedi", 
                                   font=("Segoe UI", 11), bg=self.colors['bg_medium'], fg=self.colors['text_gray'])
        self.folder_label.pack(side="left", fill="x", expand=True)
        
        select_button = tk.Button(folder_select_frame, text="📁 Klasör Seç", 
                                command=self.select_folder, font=("Segoe UI", 11, "bold"),
                                bg=self.colors['accent_blue'], fg=self.colors['text_light'], 
                                relief="flat", padx=25, pady=10, cursor="hand2")
        select_button.pack(side="right")
        
        # İndirme butonları - Daha büyük ve şık
        button_frame = tk.Frame(main_frame, bg=self.colors['bg_dark'])
        button_frame.pack(fill="x", pady=(0, 20))
        
        self.download_button = tk.Button(button_frame, text="🚀 İndirmeyi Başlat", 
                                       command=self.start_download, font=("Segoe UI", 14, "bold"),
                                       bg=self.colors['accent_green'], fg=self.colors['text_light'], 
                                       relief="flat", padx=40, pady=15, cursor="hand2")
        self.download_button.pack(side="left", padx=(0, 15))
        
        self.stop_button = tk.Button(button_frame, text="⏹️ Durdur", 
                                   command=self.stop_download, font=("Segoe UI", 12),
                                   bg="#dc3545", fg="white", relief="flat", padx=30, pady=12, state="disabled")
        self.stop_button.pack(side="left")
        
        # Hızlı indirme butonu
        quick_button = tk.Button(button_frame, text="⚡ Hızlı İndir", 
                               command=self.quick_download, font=("Segoe UI", 12),
                               bg="#ffc107", fg="black", relief="flat", padx=25, pady=12)
        quick_button.pack(side="left", padx=(10, 0))
        
                # İlerleme çubuğu - Daha detaylı ve büyük
        progress_frame = tk.LabelFrame(main_frame, text="📈 İndirme Durumu", font=("Segoe UI", 14, "bold"),
                                      bg=self.colors['bg_medium'], fg=self.colors['text_light'], relief="groove", bd=2)
        progress_frame.pack(fill="x", pady=(0, 20))
        
        # Progress bar'ı daha büyük yap
        progress_bar_frame = tk.Frame(progress_frame, bg=self.colors['bg_medium'], height=30)
        progress_bar_frame.pack(fill="x", padx=15, pady=(15, 10))
        progress_bar_frame.pack_propagate(False)
        
        self.progress_var = tk.DoubleVar()
        # Basit progress bar - style olmadan
        self.progress_bar = ttk.Progressbar(progress_bar_frame, variable=self.progress_var, maximum=100, 
                                           length=400, mode='determinate')
        self.progress_bar.pack(expand=True, fill="both", padx=5, pady=5)
        
        # İlerleme detayları
        progress_details_frame = tk.Frame(progress_frame, bg=self.colors['bg_medium'])
        progress_details_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        self.status_label = tk.Label(progress_details_frame, text="✅ Hazır", font=("Segoe UI", 11), 
                                   bg=self.colors['bg_medium'], fg=self.colors['accent_green'])
        self.status_label.pack(side="left")
        
        self.progress_text_label = tk.Label(progress_details_frame, text="0%", 
                                          bg=self.colors['bg_medium'], fg=self.colors['accent_blue'], font=("Segoe UI", 10, "bold"))
        self.progress_text_label.pack(side="right")
        
        # Progress callback'i bağla
        self.progress_var.trace("w", self.on_progress_change)
        
        # İstatistikler
        stats_frame = tk.Frame(progress_frame, bg=self.colors['bg_medium'])
        stats_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        self.files_label = tk.Label(stats_frame, text="📄 Dosyalar: 0", font=("Segoe UI", 10), 
                                  bg=self.colors['bg_medium'], fg=self.colors['text_gray'])
        self.files_label.pack(side="left", padx=(0, 20))
        
        self.size_label = tk.Label(stats_frame, text="💾 Boyut: 0 KB", font=("Segoe UI", 10), 
                                 bg=self.colors['bg_medium'], fg=self.colors['text_gray'])
        self.size_label.pack(side="left", padx=(0, 20))
        
        self.time_label = tk.Label(stats_frame, text="⏱️ Süre: 00:00", font=("Segoe UI", 10), 
                                 bg=self.colors['bg_medium'], fg=self.colors['text_gray'])
        self.time_label.pack(side="left")
        
        # Log alanı
        log_frame = tk.LabelFrame(main_frame, text="📝 İşlem Günlüğü", font=("Segoe UI", 14, "bold"),
                                bg=self.colors['bg_medium'], fg=self.colors['text_light'], relief="groove", bd=2)
        log_frame.pack(fill="both", expand=True, pady=(0, 20))
        
        # Log kontrolleri
        log_controls = tk.Frame(log_frame, bg=self.colors['bg_medium'])
        log_controls.pack(fill="x", padx=15, pady=(15, 10))
        
        clear_log_btn = tk.Button(log_controls, text="🗑️ Temizle", command=self.clear_log, 
                                font=("Segoe UI", 10), bg=self.colors['bg_light'], fg=self.colors['text_light'],
                                relief="flat", padx=15, pady=5, cursor="hand2")
        clear_log_btn.pack(side="left")
        
        save_log_btn = tk.Button(log_controls, text="💾 Kaydet", command=self.save_log, 
                               font=("Segoe UI", 10), bg=self.colors['bg_light'], fg=self.colors['text_light'],
                               relief="flat", padx=15, pady=5, cursor="hand2")
        save_log_btn.pack(side="left", padx=(10, 0))
        
        # Scrollbar ile log alanı
        log_scroll = tk.Scrollbar(log_frame)
        log_scroll.pack(side="right", fill="y")
        
        self.log_text = tk.Text(log_frame, height=10, font=("Consolas", 9), bg=self.colors['bg_light'], 
                               fg=self.colors['text_light'], yscrollcommand=log_scroll.set, 
                               relief="solid", bd=1, insertbackground=self.colors['text_light'])
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        log_scroll.config(command=self.log_text.yview)
        
        # Alt bilgi - Daha şık
        footer_frame = tk.Frame(self.root, bg=self.colors['bg_medium'], height=40)
        footer_frame.pack(fill="x", side="bottom")
        footer_frame.pack_propagate(False)
        
        footer_content = tk.Frame(footer_frame, bg=self.colors['bg_medium'])
        footer_content.pack(expand=True)
        
        footer_label = tk.Label(footer_content, text="© 2024 Web Site Arşivleyici Pro v2.0", 
                              font=("Segoe UI", 9), fg=self.colors['text_gray'], bg=self.colors['bg_medium'])
        footer_label.pack(side="left", padx=15)
        
        # GitHub linki
        github_btn = tk.Button(footer_content, text="🐙 GitHub", command=self.open_github, 
                             font=("Segoe UI", 9), bg=self.colors['bg_medium'], fg=self.colors['accent_blue'],
                             relief="flat", cursor="hand2", bd=0)
        github_btn.pack(side="right", padx=15)
        
        # Ayarları kaydet
        self.save_settings()
        
    def open_github(self):
        """GitHub sayfasını aç"""
        webbrowser.open("https://github.com/kullaniciadi/web-site-arsivleyici")
        
    def clear_log(self):
        """Log'u temizle"""
        self.log_text.delete(1.0, tk.END)
        self.log_message("🗑️ Log temizlendi")
        
    def save_log(self):
        """Log'u dosyaya kaydet"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                self.log_message(f"💾 Log kaydedildi: {filename}")
        except Exception as e:
            messagebox.showerror("Hata", f"Log kaydedilemedi: {str(e)}")
        
    def on_progress_change(self, *args):
        """İlerleme değiştiğinde çağrılır"""
        try:
            progress = self.progress_var.get()
            self.progress_text_label.config(text=f"{progress:.1f}%")
            
            # İlerleme rengini güncelle
            if progress < 25:
                self.progress_text_label.config(fg=self.colors['accent_red'])  # Kırmızı
            elif progress < 75:
                self.progress_text_label.config(fg=self.colors['accent_yellow'])  # Sarı
            else:
                self.progress_text_label.config(fg=self.colors['accent_green'])  # Yeşil
            
            # Progress bar'ı güncelle - daha güvenilir
            self.progress_bar.configure(value=progress)
            self.root.update_idletasks()
                
        except Exception as e:
            print(f"Progress güncelleme hatası: {e}")
        
    def select_folder(self):
        """Klasör seçimi"""
        folder = filedialog.askdirectory()
        if folder:
            self.output_folder = folder
            self.folder_label.config(text=f"📁 {folder}", fg="#28a745")
            self.log_message(f"Klasör seçildi: {folder}")
    
    def quick_download(self):
        """Hızlı indirme - sadece ana sayfa"""
        if not self.url_entry.get().strip() or not self.output_folder:
            messagebox.showerror("Hata", "Lütfen URL ve kayıt klasörünü belirtin.")
            return
        
        self.depth_var.set("1")
        self.delay_var.set("1")
        self.start_download()
    
    def log_message(self, message):
        """Log mesajı ekle"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def start_download(self):
        """İndirmeyi başlat"""
        if not self.url_entry.get().strip() or not self.output_folder:
            messagebox.showerror("Hata", "Lütfen URL ve kayıt klasörünü belirtin.")
            return
        
        if self.is_downloading:
            return
        
        self.is_downloading = True
        self.download_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress_var.set(0)
        self.status_label.config(text="İndiriliyor...", fg="#007bff")
        
        # Başlangıç zamanı
        self.start_time = datetime.now()
        
        # Ayrı thread'de indirme işlemi
        download_thread = threading.Thread(target=self.download_process)
        download_thread.daemon = True
        download_thread.start()
    
    def download_process(self):
        """İndirme işlemi"""
        try:
            url = self.url_entry.get().strip()
            depth = int(self.depth_var.get())
            delay = int(self.delay_var.get())
            
            self.log_message(f"🚀 İndirme başlatılıyor: {url}")
            self.log_message(f"🔍 Derinlik: {depth}, ⏱️ Gecikme: {delay}s")
            
            # Progress callback wrapper - thread-safe
            def progress_callback(percentage):
                self.root.after(0, lambda: self.progress_var.set(percentage))
            
            # Crawler'ı çağır
            crawl_site(url, self.output_folder, depth, delay, self.log_message, progress_callback)
            
            if self.is_downloading:  # Durdurulmadıysa
                self.root.after(0, self.download_completed)
                
        except Exception as e:
            self.root.after(0, lambda: self.download_error(str(e)))
    
    def download_completed(self):
        """İndirme tamamlandı"""
        self.is_downloading = False
        self.download_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.progress_var.set(100)
        self.status_label.config(text="Tamamlandı!", fg="#28a745")
        
        # Süreyi hesapla
        end_time = datetime.now()
        duration = end_time - self.start_time
        self.time_label.config(text=f"⏱️ Süre: {duration.strftime('%M:%S')}")
        
        self.log_message("✅ İndirme başarıyla tamamlandı!")
        messagebox.showinfo("Başarılı", "Site başarıyla arşivlendi!")
    
    def download_error(self, error_msg):
        """İndirme hatası"""
        self.is_downloading = False
        self.download_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_label.config(text="❌ Hata oluştu", fg=self.colors['accent_red'])
        self.log_message(f"❌ Hata: {error_msg}")
        messagebox.showerror("Hata", f"İndirme sırasında hata oluştu:\n{error_msg}")
    
    def stop_download(self):
        """İndirmeyi durdur"""
        self.is_downloading = False
        self.download_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_label.config(text="⏹️ Durduruldu", fg=self.colors['text_gray'])
        self.log_message("⏹️ İndirme durduruldu")
        
        # Crawler'ı durdur
        if self.crawler:
            self.crawler.stop()
    
    def add_to_history(self):
        """İndirme geçmişine ekle"""
        history_item = {
            'url': self.url_entry.get().strip(),
            'folder': self.output_folder,
            'depth': self.depth_var.get(),
            'delay': self.delay_var.get(),
            'date': datetime.now().isoformat(),
            'status': 'completed'
        }
        self.download_history.append(history_item)
        self.save_download_history()
    
    def save_download_history(self):
        """İndirme geçmişini kaydet"""
        try:
            with open('download_history.json', 'w', encoding='utf-8') as f:
                json.dump(self.download_history, f, indent=2, ensure_ascii=False)
        except:
            pass
    
    def load_download_history(self):
        """İndirme geçmişini yükle"""
        try:
            with open('download_history.json', 'r', encoding='utf-8') as f:
                self.download_history = json.load(f)
        except:
            self.download_history = []
    
    def run(self):
        """Uygulamayı çalıştır"""
        self.root.mainloop()

# Eski sınıf adını koru (geriye uyumluluk için)
SiteDownloaderGUI = ModernSiteDownloader
