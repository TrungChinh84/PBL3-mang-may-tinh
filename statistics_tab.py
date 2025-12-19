# statistics_tab.py
import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.dates as mdates
from datetime import datetime, timedelta
import json
import subprocess
from collections import defaultdict, deque
import threading
import time
import os

class StatisticsTab:
    def __init__(self, parent):
        self.parent = parent
        self.connection_data = deque(maxlen=100)  # Lưu 100 điểm dữ liệu
        self.alert_data = deque(maxlen=50)       # Lưu 50 cảnh báo
        self.ip_connections = defaultdict(int)
        
        self.setup_matplotlib()
        self.create_widgets()
        self.start_data_collection()
    
    def setup_matplotlib(self):
        """Thiết lập matplotlib với style"""
        try:
            plt.style.use('ggplot')
        except Exception:
            pass
        self.fig, ((self.ax1, self.ax2), (self.ax3, self.ax4)) = plt.subplots(2, 2, figsize=(12, 8))
        self.fig.tight_layout(pad=3.0)
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top frame for controls
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(control_frame, text="Làm Mới", command=self.refresh_data).pack(side=tk.LEFT)
        ttk.Button(control_frame, text="Xuất Báo Cáo", command=self.export_report).pack(side=tk.LEFT, padx=5)
        
        # Matplotlib canvas
        canvas_frame = ttk.Frame(main_frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.canvas = FigureCanvasTkAgg(self.fig, canvas_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Bottom frame for alerts and top IPs
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=5)
        
        # Alerts frame
        alerts_frame = ttk.LabelFrame(bottom_frame, text="Cảnh Báo Gần Đây")
        alerts_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        self.alerts_text = tk.Text(alerts_frame, height=8, width=60)
        alerts_scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_text.yview)
        self.alerts_text.config(yscrollcommand=alerts_scrollbar.set)
        self.alerts_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        alerts_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Top IPs frame
        top_ips_frame = ttk.LabelFrame(bottom_frame, text="Top IP Kết Nối Nhiều Nhất")
        top_ips_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self.top_ips_text = tk.Text(top_ips_frame, height=8, width=30)
        top_ips_scrollbar = ttk.Scrollbar(top_ips_frame, orient=tk.VERTICAL, command=self.top_ips_text.yview)
        self.top_ips_text.config(yscrollcommand=top_ips_scrollbar.set)
        self.top_ips_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        top_ips_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Initial data load
        self.refresh_data()
    
    def start_data_collection(self):
        """Bắt đầu thu thập dữ liệu trong thread riêng"""
        def collect_data():
            while True:
                try:
                    self.collect_connection_stats()
                    self.collect_alerts()
                    # update displays on main thread via after to be thread-safe
                    try:
                        self.parent.after(0, self.update_displays)
                    except Exception:
                        self.update_displays()
                    time.sleep(10)  # Cập nhật mỗi 10 giây
                except Exception as e:
                    print(f"Lỗi thu thập dữ liệu: {e}")
                    time.sleep(30)
        
        thread = threading.Thread(target=collect_data, daemon=True)
        thread.start()
    
    def collect_connection_stats(self):
        """Thu thập thống kê kết nối"""
        try:
            result = subprocess.run(['ss', '-tn'], capture_output=True, text=True)
            connection_count = 0
            current_ips = defaultdict(int)
            
            for line in result.stdout.split('\n'):
                if 'ESTAB' in line or 'SYN-' in line:
                    connection_count += 1
                    parts = line.split()
                    # phần địa chỉ thường ở cột 4 hoặc 5 tùy output, cố gắng lấy cột cuối
                    if len(parts) >= 1:
                        ipport = parts[-1]
                        ip = ipport.split(':')[0]
                        if self.is_valid_ip(ip):
                            current_ips[ip] += 1
            
            # Cập nhật dữ liệu
            timestamp = datetime.now()
            self.connection_data.append((timestamp, connection_count))
            self.ip_connections = current_ips
            
        except Exception as e:
            print(f"Lỗi thu thập thống kê: {e}")
    
    def collect_alerts(self):
        """Thu thập cảnh báo từ file log"""
        try:
            alert_file = '/var/log/firewall_alerts.json'
            if os.path.exists(alert_file):
                with open(alert_file, 'r') as f:
                    try:
                        alerts = json.load(f)
                    except json.JSONDecodeError:
                        alerts = []
                
                # Chỉ lấy alerts mới (10 gần nhất)
                for alert in alerts[-10:]:
                    # chấp nhận alert có 'timestamp','ip','reason' hoặc ko
                    ts = alert.get('timestamp') if isinstance(alert, dict) else None
                    ip = alert.get('ip') if isinstance(alert, dict) else str(alert)
                    reason = alert.get('reason', '') if isinstance(alert, dict) else ''
                    try:
                        alert_time = datetime.fromtimestamp(int(ts)) if ts else datetime.now()
                    except Exception:
                        alert_time = datetime.now()
                    alert_text = f"{alert_time.strftime('%Y-%m-%d %H:%M:%S')} - {ip} - {reason}\n"
                    
                    if alert_text not in self.alert_data:
                        self.alert_data.append(alert_text)
        except Exception as e:
            print(f"Lỗi thu thập cảnh báo: {e}")
    
    def update_displays(self):
        """Cập nhật hiển thị"""
        self.update_charts()
        self.update_alerts_text()
        self.update_top_ips_text()
    
    def update_charts(self):
        """Cập nhật biểu đồ"""
        # Clear all axes
        for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
            ax.clear()
        
        # Biểu đồ 1: Tổng số kết nối theo thời gian
        if self.connection_data:
            times, connections = zip(*self.connection_data)
            self.ax1.plot(times, connections, linewidth=2)
            self.ax1.set_title('Tổng Số Kết Nối Theo Thời Gian')
            self.ax1.set_ylabel('Số Kết Nối')
            self.ax1.tick_params(axis='x', rotation=45)
            self.ax1.grid(True, alpha=0.3)
            # format datetime x-axis
            try:
                self.ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            except Exception:
                pass
        
        # Biểu đồ 2: Phân loại kết nối (giả lập)
        connection_types = ['ESTABLISHED', 'SYN-SENT', 'SYN-RECEIVED', 'TIME-WAIT']
        total = max(1, len(self.connection_data))
        connection_counts = [total * 0.6, total * 0.1, total * 0.1, total * 0.2]
        self.ax2.pie(connection_counts, labels=connection_types, autopct='%1.1f%%')
        self.ax2.set_title('Phân Loại Kết Nối')
        
        # Biểu đồ 3: Top 5 IP có nhiều kết nối nhất
        if self.ip_connections:
            top_ips = sorted(self.ip_connections.items(), key=lambda x: x[1], reverse=True)[:5]
            ips, counts = zip(*top_ips) if top_ips else ([], [])
            self.ax3.bar(range(len(ips)), counts)
            self.ax3.set_xticks(range(len(ips)))
            self.ax3.set_xticklabels(ips, rotation=45)
            self.ax3.set_title('Top 5 IP Nhiều Kết Nối Nhất')
        
        # Biểu đồ 4: Số lượng cảnh báo (giả lập)
        hours = [f'{i:02d}:00' for i in range(24)]
        alert_counts = [max(0, len(self.alert_data) // 24 + (i % 3)) for i in range(24)]
        self.ax4.bar(hours, alert_counts, alpha=0.7)
        self.ax4.set_title('Cảnh Báo Theo Giờ')
        self.ax4.tick_params(axis='x', rotation=45)
        try:
            self.canvas.draw()
        except Exception:
            pass
    
    def update_alerts_text(self):
        """Cập nhật text cảnh báo"""
        try:
            self.alerts_text.delete(1.0, tk.END)
            for alert in list(self.alert_data)[-10:]:  # Hiển thị 10 cảnh báo gần nhất
                self.alerts_text.insert(tk.END, alert)
        except Exception as e:
            print(f"Lỗi update_alerts_text: {e}")
    
    def update_top_ips_text(self):
        """Cập nhật top IP"""
        try:
            self.top_ips_text.delete(1.0, tk.END)
            if self.ip_connections:
                top_ips = sorted(self.ip_connections.items(), key=lambda x: x[1], reverse=True)[:10]
                for ip, count in top_ips:
                    self.top_ips_text.insert(tk.END, f"{ip}: {count} kết nối\n")
            else:
                self.top_ips_text.insert(tk.END, "Không có dữ liệu")
        except Exception as e:
            print(f"Lỗi update_top_ips_text: {e}")
    
    def refresh_data(self):
        """Làm mới dữ liệu"""
        self.collect_connection_stats()
        self.collect_alerts()
        self.update_displays()
    
    def export_report(self):
        """Xuất báo cáo thống kê"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"/tmp/firewall_report_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write("BÁO CÁO THỐNG KÊ FIREWALL\n")
                f.write("=" * 50 + "\n")
                f.write(f"Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("THỐNG KÊ KẾT NỐI:\n")
                f.write(f"- Tổng số kết nối theo dõi: {len(self.connection_data)}\n")
                f.write(f"- Số IP duy nhất: {len(self.ip_connections)}\n\n")
                
                f.write("TOP IP KẾT NỐI NHIỀU NHẤT:\n")
                if self.ip_connections:
                    top_ips = sorted(self.ip_connections.items(), key=lambda x: x[1], reverse=True)[:10]
                    for i, (ip, count) in enumerate(top_ips, 1):
                        f.write(f"{i:2d}. {ip}: {count} kết nối\n")
                f.write("\n")
                
                f.write("CẢNH BÁO GẦN ĐÂY:\n")
                for alert in list(self.alert_data)[-10:]:
                    f.write(alert)
            
            messagebox.showinfo("Thành công", f"Đã xuất báo cáo: {filename}")
            
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể xuất báo cáo: {e}")
    
    def is_valid_ip(self, ip):
        """Kiểm tra IP hợp lệ"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
