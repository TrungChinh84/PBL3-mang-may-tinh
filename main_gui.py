#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import os
import sys
import json
from datetime import datetime, timezone

# Import các tab nếu có
try:
    from firewall_tab import FirewallTab
    from auto_block_tab import AutoBlockTab
    from statistics_tab import StatisticsTab
    from fail2ban_tab import Fail2BanTab
except ImportError:
    FirewallTab = None
    AutoBlockTab = None
    StatisticsTab = None
    Fail2BanTab = None

LOG_JSON = '/var/log/firewall_alerts.json'
LOG_PLAIN = '/var/log/firewall_auto_block.log'


class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Management System - PBL4")
        self.root.geometry("1200x800")

        # Kiểm tra quyền root
        self.check_root_privileges()

        # Chạy auto_block.py nền
        self.start_auto_block_script()

        # Các biến UI động
        self.blocked_count_var = tk.StringVar(value="0")
        self.today_alerts_var = tk.StringVar(value="0")
        self.auto_block_status_var = tk.StringVar(value="TẮT")

        # Tạo giao diện
        self.setup_gui()

        # Cập nhật dashboard từ logs
        self.update_dashboard_from_logs()
        self._after_id = self.root.after(5000, self.periodic_update)

    # ----------------- Root & Privileges -----------------
    def check_root_privileges(self):
        if os.geteuid() != 0:
            messagebox.showerror(
                "Lỗi Quyền Truy Cập",
                "Ứng dụng cần chạy với quyền root!\nHãy chạy: sudo python3 main_gui.py"
            )
            sys.exit(1)

    def start_auto_block_script(self):
        script_path = os.path.join(os.path.dirname(__file__), 'auto_block.py')
        if not os.path.exists(script_path):
            print(f"Không tìm thấy {script_path}, bỏ qua auto-block")
            return
        try:
            self.auto_block_process = subprocess.Popen(
                [sys.executable, script_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("Auto-block script đã chạy nền")
        except Exception as e:
            print(f"Lỗi chạy auto-block script: {e}")

    # ----------------- GUI Setup -----------------
    def setup_gui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.setup_dashboard_tab()
        self.setup_firewall_tab()
        self.setup_auto_block_tab()
        self.setup_statistics_tab()
        self.setup_fail2ban_tab()
        # Đã xóa setup_settings_tab ở đây theo yêu cầu
        
        self.setup_status_bar()

    def setup_dashboard_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Dashboard")

# Quick actions
        actions_frame = ttk.LabelFrame(frame, text="Hành Động Nhanh")
        actions_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(actions_frame, text="Xem Rules IPTables", command=self.show_iptables_rules).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Kiểm Tra Dịch Vụ", command=self.check_services).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Xem Logs", command=self.view_logs).pack(side=tk.LEFT, padx=5)
        
        # --- THÊM DÒNG NÀY ---
        ttk.Button(actions_frame, text="Xóa Lịch Sử Log", command=self.clear_logs).pack(side=tk.RIGHT, padx=5)
        # Header
        header = ttk.Frame(frame)
        header.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(header, text="Firewall Management System", font=('Arial', 16, 'bold')).pack(side=tk.LEFT)
        ttk.Button(header, text="Làm Mới Tất Cả", command=self.refresh_all).pack(side=tk.RIGHT)

        # Statistics cards
        stats_frame = ttk.Frame(frame)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        for title, var in [("IP Bị Chặn", self.blocked_count_var),
                           ("Cảnh Báo Hôm Nay", self.today_alerts_var),
                           ("Tự Động Chặn", self.auto_block_status_var)]:
            card = ttk.LabelFrame(stats_frame, text=title)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            ttk.Label(card, textvariable=var, font=('Arial', 24, 'bold'), foreground='red' if title=="Tự Động Chặn" else None).pack(pady=20)

        # Recent alerts
        alerts_frame = ttk.LabelFrame(frame, text="Cảnh Báo Gần Đây")
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.alerts_text = tk.Text(alerts_frame, height=12)
        scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_text.yview)
        self.alerts_text.config(yscrollcommand=scrollbar.set)
        self.alerts_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.alerts_text.insert(tk.END, "Chưa có cảnh báo nào...\n")
        self.alerts_text.config(state=tk.DISABLED)

        # Quick actions
        actions_frame = ttk.LabelFrame(frame, text="Hành Động Nhanh")
        actions_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(actions_frame, text="Xem Rules IPTables", command=self.show_iptables_rules).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Kiểm Tra Dịch Vụ", command=self.check_services).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Xem Logs", command=self.view_logs).pack(side=tk.LEFT, padx=5)

    def setup_firewall_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Firewall")
        if FirewallTab:
            self.firewall_tab = FirewallTab(frame)
        else:
            ttk.Label(frame, text="Lỗi: Không tìm thấy file firewall_tab.py").pack(pady=20)

    def setup_auto_block_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Tự Động Chặn")
        if AutoBlockTab:
            self.auto_block_tab = AutoBlockTab(frame)
        else:
            ttk.Label(frame, text="AutoBlockTab chưa được cài đặt").pack(pady=20)

    def setup_statistics_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Thống Kê")
        if StatisticsTab:
            self.stats_tab = StatisticsTab(frame)
        else:
            ttk.Label(frame, text="StatisticsTab chưa được cài đặt").pack(pady=20)

    def setup_fail2ban_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Fail2Ban")
        if Fail2BanTab:
            self.fail2ban_tab = Fail2BanTab(frame)
        else:
            ttk.Label(frame, text="Fail2BanTab chưa được cài đặt").pack(pady=20)

    # Đã xóa hàm setup_settings_tab()

    def setup_status_bar(self):
        frame = ttk.Frame(self.root)
        frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_var = tk.StringVar(value="Sẵn sàng")
        ttk.Label(frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        ttk.Label(frame, text="PBL4 - Linux Firewall System").pack(side=tk.RIGHT, padx=5)

    # ----------------- Dashboard Functions -----------------
    def clear_logs(self):
        """Hàm xóa sạch lịch sử log"""
        confirm = messagebox.askyesno(
            "Xác nhận xóa", 
            "Bạn có chắc chắn muốn xóa toàn bộ lịch sử cảnh báo và log không?\nHành động này không thể hoàn tác."
        )
        
        if confirm:
            try:
                # 1. Reset file JSON về mảng rỗng []
                if os.path.exists(LOG_JSON):
                    with open(LOG_JSON, 'w') as f:
                        f.write('[]') 
                
                # 2. Xóa trắng file log thường
                if os.path.exists(LOG_PLAIN):
                    open(LOG_PLAIN, 'w').close()
                
                messagebox.showinfo("Thành công", "Đã xóa sạch lịch sử log!")
                
                # 3. Cập nhật lại giao diện ngay lập tức
                self.refresh_all()
                
            except PermissionError:
                messagebox.showerror("Lỗi Quyền", "Không thể ghi file log.\nHãy chắc chắn bạn chạy app bằng sudo!")
            except Exception as e:
                messagebox.showerror("Lỗi", f"Có lỗi xảy ra: {e}")
    def load_alerts(self):
        if not os.path.exists(LOG_JSON):
            return []
        try:
            with open(LOG_JSON, 'r') as f:
                data = f.read().strip()
                if not data:
                    return []
                try:
                    alerts = json.loads(data)
                    if isinstance(alerts, dict):
                        return [alerts]
                    if isinstance(alerts, list):
                        return alerts
                    return []
                except json.JSONDecodeError:
                    alerts = []
                    for line in data.splitlines():
                        line = line.strip()
                        if line:
                            try:
                                alerts.append(json.loads(line))
                            except:
                                continue
                    return alerts
        except Exception as e:
            print("Lỗi đọc log JSON:", e)
            return []

    def update_dashboard_from_logs(self):
        alerts = self.load_alerts()
        # Logic cập nhật Dashboard
        if not alerts:
            self.blocked_count_var.set("0")
            self.today_alerts_var.set("0")
            self.auto_block_status_var.set("TẮT")
            self.alerts_text.config(state=tk.NORMAL)
            self.alerts_text.delete(1.0, tk.END)
            self.alerts_text.insert(tk.END, "Chưa có cảnh báo nào...\n")
            self.alerts_text.config(state=tk.DISABLED)
            return

        blocked_ips = set()
        today_count = 0
        recent_lines = []

        now = datetime.now(timezone.utc)
        midnight = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)

        for entry in alerts:
            ts = entry.get('timestamp')
            ip = entry.get('ip') or entry.get('src_ip') or entry.get('source')
            action = entry.get('action', '').upper() if entry.get('action') else ''
            reason = entry.get('reason', '')

            if action == 'BLOCKED' and ip:
                blocked_ips.add(ip)

            try:
                entry_dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
                if entry_dt >= midnight:
                    today_count += 1
            except Exception:
                today_count += 1

            try:
                time_str = datetime.fromtimestamp(float(ts), tz=timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S')
            except:
                time_str = str(ts)
            recent_lines.append(f"{time_str} - {ip or 'unknown'} - {action} - {reason}")

        recent_lines = list(reversed(recent_lines[-50:]))

        self.blocked_count_var.set(str(len(blocked_ips)))
        self.today_alerts_var.set(str(today_count))
        self.auto_block_status_var.set("BẬT" if any((entry.get('action','').upper()=='BLOCKED') for entry in alerts) else "TẮT")

        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.delete(1.0, tk.END)
        for line in recent_lines:
            self.alerts_text.insert(tk.END, line + "\n")
        self.alerts_text.config(state=tk.DISABLED)

    def periodic_update(self):
        try:
            self.update_dashboard_from_logs()
        except Exception as e:
            print("Lỗi periodic_update:", e)
        self._after_id = self.root.after(5000, self.periodic_update)

    # ----------------- Quick Actions -----------------
    def show_iptables_rules(self):
        try:
            result = subprocess.run(['iptables', '-L', '-n', '-v'], capture_output=True, text=True)
            win = tk.Toplevel(self.root)
            win.title("IPTables Rules")
            win.geometry("800x600")
            text = tk.Text(win, wrap=tk.NONE)
            yscroll = ttk.Scrollbar(win, orient=tk.VERTICAL, command=text.yview)
            xscroll = ttk.Scrollbar(win, orient=tk.HORIZONTAL, command=text.xview)
            text.config(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
            text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            yscroll.pack(side=tk.RIGHT, fill=tk.Y)
            xscroll.pack(side=tk.BOTTOM, fill=tk.X)
            text.insert(tk.END, result.stdout)
            text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể lấy rules: {e}")

    def check_services(self):
        services = {
            'firewall-auto-block': 'Tự động chặn',
            'fail2ban': 'Fail2Ban',
            'iptables': 'IPTables'
        }
        status_text = ""
        for svc, name in services.items():
            try:
                if svc == 'iptables':
                    subprocess.run(['iptables', '-L'], capture_output=True, check=True)
                    status = "Đang chạy"
                else:
                    result = subprocess.run(['systemctl', 'is-active', svc], capture_output=True, text=True)
                    status = "Đang chạy" if result.stdout.strip() == 'active' else "Dừng"
                status_text += f"• {name}: {status}\n"
            except:
                status_text += f"• {name}: Lỗi\n"
        messagebox.showinfo("Trạng Thái Dịch Vụ", status_text)

    def view_logs(self):
        win = tk.Toplevel(self.root)
        win.title("System Logs")
        win.geometry("800x600")
        text = tk.Text(win)
        scrollbar = ttk.Scrollbar(win, orient=tk.VERTICAL, command=text.yview)
        text.config(yscrollcommand=scrollbar.set)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        try:
            for log_file in [LOG_PLAIN, LOG_JSON]:
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        text.insert(tk.END, f"=== {log_file} ===\n{f.read()}\n\n")
        except Exception as e:
            text.insert(tk.END, f"Lỗi đọc log: {e}")
        text.config(state=tk.DISABLED)

    def refresh_all(self):
        self.status_var.set("Đang làm mới dữ liệu...")
        
        # 1. Refresh Auto Block Tab
        if hasattr(self, 'auto_block_tab') and hasattr(self.auto_block_tab, 'check_service_status'):
            try: self.auto_block_tab.check_service_status()
            except: pass
            
        # 2. Refresh Stats Tab
        if hasattr(self, 'stats_tab') and hasattr(self.stats_tab, 'refresh_data'):
            try: self.stats_tab.refresh_data()
            except: pass
            
        # 3. Refresh Fail2Ban Tab
        if hasattr(self, 'fail2ban_tab') and hasattr(self.fail2ban_tab, 'refresh_status'):
            try: self.fail2ban_tab.refresh_status()
            except: pass

        # 4. Refresh Firewall Tab (IPTables Rules) -> ĐÃ BỔ SUNG PHẦN NÀY
        if hasattr(self, 'firewall_tab') and hasattr(self.firewall_tab, 'load_rules'):
            try: self.firewall_tab.load_rules()
            except: pass

        self.update_dashboard_from_logs()
        self.status_var.set("Đã làm mới dữ liệu")
        messagebox.showinfo("Thành công", "Đã làm mới tất cả dữ liệu")

    def on_close(self):
        try:
            if hasattr(self, '_after_id') and self._after_id:
                self.root.after_cancel(self._after_id)
            if hasattr(self, 'auto_block_process') and self.auto_block_process:
                self.auto_block_process.terminate()
        except Exception:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = FirewallGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
