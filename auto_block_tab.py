import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import json
import os

class AutoBlockTab:
    def __init__(self, parent):
        self.parent = parent
        # File config này phải khớp với file mà script chạy ngầm đọc
        self.config_file = "/etc/firewall_auto_block.json" 
        self.service_name = "firewall-auto-block"
        
        self.create_widgets()
        self.load_config()
    
    def create_widgets(self):
        # Main frame có scrollbar nếu màn hình bé (Optional, ở đây dùng pack đơn giản)
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # --- 1. Status Frame ---
        status_frame = ttk.LabelFrame(main_frame, text="Trạng Thái Dịch Vụ")
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_var = tk.StringVar(value="Đang kiểm tra...")
        lbl_status = ttk.Label(status_frame, textvariable=self.status_var, font=('Arial', 10, 'bold'))
        lbl_status.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.toggle_btn = ttk.Button(status_frame, text="Bật Tự Động", command=self.toggle_auto_block)
        self.toggle_btn.pack(side=tk.RIGHT, padx=10, pady=10)
        
        # --- 2. Configuration Frame ---
        config_frame = ttk.LabelFrame(main_frame, text="Cấu Hình Ngưỡng & Thời Gian")
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Grid layout cho config
        # Row 0: SYN Threshold
        ttk.Label(config_frame, text="Ngưỡng SYN Flood (gói/phút):").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.syn_threshold = tk.StringVar()
        ttk.Spinbox(config_frame, from_=10, to=10000, textvariable=self.syn_threshold, width=10).grid(row=0, column=1, padx=5)
        
        # Row 1: Connection Threshold
        ttk.Label(config_frame, text="Ngưỡng Kết Nối (conn/phút):").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.conn_threshold = tk.StringVar()
        ttk.Spinbox(config_frame, from_=10, to=10000, textvariable=self.conn_threshold, width=10).grid(row=1, column=1, padx=5)
        
        # Row 2: Ban Time (MỚI THÊM)
        ttk.Label(config_frame, text="Thời gian chặn (giây):").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        self.ban_time = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.ban_time, width=10).grid(row=2, column=1, padx=5)
        ttk.Label(config_frame, text="(300s = 5 phút)").grid(row=2, column=2, sticky=tk.W)

        # Row 3: Check Interval
        ttk.Label(config_frame, text="Chu kỳ kiểm tra (giây):").grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
        self.check_interval = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.check_interval, width=10).grid(row=3, column=1, padx=5)
        
        # Save button
        ttk.Button(config_frame, text="Lưu Cấu Hình", command=self.save_config).grid(row=4, column=0, columnspan=3, pady=10)
        
        # --- 3. Whitelist Frame ---
        whitelist_frame = ttk.LabelFrame(main_frame, text="IP Whitelist (Danh Sách Tin Cậy)")
        whitelist_frame.pack(fill=tk.BOTH, expand=True)
        
        # Control area
        wl_ctrl = ttk.Frame(whitelist_frame)
        wl_ctrl.pack(fill=tk.X, padx=5, pady=5)
        
        self.new_ip_var = tk.StringVar()
        ttk.Entry(wl_ctrl, textvariable=self.new_ip_var, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(wl_ctrl, text="Thêm IP", command=self.add_whitelist_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(wl_ctrl, text="Xóa IP Đã Chọn", command=self.remove_whitelist_ip).pack(side=tk.RIGHT, padx=5)
        
        # Listbox
        list_frame = ttk.Frame(whitelist_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.whitelist_listbox = tk.Listbox(list_frame, height=6)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.whitelist_listbox.yview)
        self.whitelist_listbox.config(yscrollcommand=scrollbar.set)
        
        self.whitelist_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Khởi tạo
        self.check_service_status()
    
    def check_service_status(self):
        """Kiểm tra trạng thái systemd service"""
        try:
            # Kiểm tra active
            result = subprocess.run(['systemctl', 'is-active', self.service_name], capture_output=True, text=True)
            status_text = result.stdout.strip()
            
            if status_text == 'active':
                self.status_var.set("ĐANG BẬT (Service is Running)")
                self.toggle_btn.config(text="Tắt Dịch Vụ")
                # Tô màu xanh cho text (nếu dùng label style) hoặc chỉ text
            else:
                self.status_var.set("ĐANG TẮT (Service Stopped)")
                self.toggle_btn.config(text="Bật Dịch Vụ")
        except FileNotFoundError:
             self.status_var.set("Lỗi: Không tìm thấy systemctl")
        except Exception as e:
            self.status_var.set(f"Lỗi: {str(e)}")
    
    def toggle_auto_block(self):
        """Bật/tắt service"""
        try:
            current = self.status_var.get()
            if "ĐANG BẬT" in current:
                subprocess.run(['systemctl', 'stop', self.service_name], check=True)
                # subprocess.run(['systemctl', 'disable', self.service_name], check=True) # Tùy chọn
                messagebox.showinfo("Thông báo", "Đã dừng dịch vụ tự động chặn.")
            else:
                subprocess.run(['systemctl', 'start', self.service_name], check=True)
                # subprocess.run(['systemctl', 'enable', self.service_name], check=True) # Tùy chọn
                messagebox.showinfo("Thông báo", "Đã khởi động dịch vụ.")
            
            self.parent.after(1000, self.check_service_status) # Kiểm tra lại sau 1s
            
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Lỗi Systemctl", f"Không thể thay đổi trạng thái dịch vụ.\nBạn có đang chạy với quyền sudo không?\n\nLỗi: {e}")

    def load_config(self):
        default_config = {
            'syn_threshold': 50,
            'conn_threshold': 100,
            'ban_time': 300,
            'check_interval': 10,
            'whitelist': ['127.0.0.1']
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
            else:
                config = default_config
        except:
            config = default_config
        
        self.syn_threshold.set(config.get('syn_threshold', 50))
        self.conn_threshold.set(config.get('conn_threshold', 100))
        self.ban_time.set(config.get('ban_time', 300))
        self.check_interval.set(config.get('check_interval', 10))
        
        self.whitelist_listbox.delete(0, tk.END)
        for ip in config.get('whitelist', []):
            self.whitelist_listbox.insert(tk.END, ip)

    def save_config(self):
        try:
            config = {
                'syn_threshold': int(self.syn_threshold.get()),
                'conn_threshold': int(self.conn_threshold.get()),
                'ban_time': int(self.ban_time.get()),
                'check_interval': int(self.check_interval.get()),
                'whitelist': list(self.whitelist_listbox.get(0, tk.END))
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            
            messagebox.showinfo("Thành công", "Đã lưu cấu hình.\nNếu dịch vụ đang chạy, nó sẽ tự cập nhật ở chu kỳ tiếp theo.")
            
        except ValueError:
            messagebox.showerror("Lỗi nhập liệu", "Vui lòng nhập số nguyên hợp lệ cho các trường cấu hình.")
        except PermissionError:
             messagebox.showerror("Lỗi quyền", f"Không thể ghi file {self.config_file}.\nHãy chạy chương trình bằng sudo.")

    def add_whitelist_ip(self):
        ip = self.new_ip_var.get().strip()
        if not ip: return
        # Validate sơ bộ
        if ip.count('.') != 3:
            messagebox.showwarning("Lỗi IP", "Định dạng IP không hợp lệ")
            return
        
        if ip not in self.whitelist_listbox.get(0, tk.END):
            self.whitelist_listbox.insert(tk.END, ip)
            self.new_ip_var.set("")
    
    def remove_whitelist_ip(self):
        sel = self.whitelist_listbox.curselection()
        if sel:
            self.whitelist_listbox.delete(sel)
