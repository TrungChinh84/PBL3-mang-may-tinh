import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import subprocess
import os

class Fail2BanTab:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- Toolbar ---
        toolbar = ttk.Frame(self.frame)
        toolbar.pack(fill=tk.X, pady=5)
        
        ttk.Button(toolbar, text="Làm Mới Danh Sách", command=self.refresh_status).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Gỡ Chặn (Unban) IP", command=self.unban_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Xem Log Fail2Ban", command=self.view_log).pack(side=tk.LEFT, padx=5)

        # --- Jail Selection ---
        filter_frame = ttk.Frame(self.frame)
        filter_frame.pack(fill=tk.X, pady=5)
        ttk.Label(filter_frame, text="Chọn Jail (Lồng giam):").pack(side=tk.LEFT, padx=5)
        self.jail_var = tk.StringVar(value="sshd")
        # Bạn có thể thêm các jail khác vào list này (vd: apache-auth, vsftpd)
        self.jail_combo = ttk.Combobox(filter_frame, textvariable=self.jail_var, values=["sshd", "apache-auth"], width=15)
        self.jail_combo.pack(side=tk.LEFT, padx=5)
        self.jail_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_status())

        # --- Listbox hiển thị IP ---
        columns = ("jail", "ip")
        self.tree = ttk.Treeview(self.frame, columns=columns, show='headings', height=15)
        self.tree.heading("jail", text="Jail")
        self.tree.heading("ip", text="Địa chỉ IP bị chặn")
        self.tree.column("jail", width=100, anchor=tk.CENTER)
        self.tree.column("ip", width=300)
        
        scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.refresh_status()

    def refresh_status(self):
        """Lấy danh sách IP bị chặn từ fail2ban-client"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        jail = self.jail_var.get()
        try:
            # Lệnh: fail2ban-client status sshd
            cmd = ['fail2ban-client', 'status', jail]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                # Nếu jail không chạy hoặc không tồn tại
                return

            # Phân tích output để tìm dòng "Banned IP list:"
            for line in result.stdout.splitlines():
                if "Banned IP list:" in line:
                    # Cắt chuỗi để lấy các IP phía sau dấu :
                    content = line.split(":", 1)[1].strip()
                    if content:
                        ips = content.split()
                        for ip in ips:
                            self.tree.insert("", tk.END, values=(jail, ip))
                    break

        except FileNotFoundError:
            messagebox.showerror("Lỗi", "Chưa cài đặt Fail2Ban hoặc không tìm thấy lệnh fail2ban-client.")
        except Exception as e:
            print(f"Lỗi Fail2Ban: {e}")

    def unban_ip(self):
        """Gỡ bỏ IP khỏi danh sách chặn"""
        selected = self.tree.selection()
        if not selected:
            # Nếu không chọn trong list, cho nhập tay
            ip = simpledialog.askstring("Unban", "Nhập IP muốn gỡ chặn:")
            if not ip: return
            jail = self.jail_var.get()
        else:
            item = self.tree.item(selected[0])
            jail = item['values'][0]
            ip = item['values'][1]

        if not ip: return

        confirm = messagebox.askyesno("Xác nhận", f"Bạn có chắc muốn Unban IP {ip} khỏi {jail}?")
        if confirm:
            try:
                # Lệnh: fail2ban-client set <jail> unbanip <ip>
                cmd = ['fail2ban-client', 'set', jail, 'unbanip', ip]
                subprocess.run(cmd, check=True)
                messagebox.showinfo("Thành công", f"Đã gỡ chặn IP {ip}")
                self.refresh_status()
            except subprocess.CalledProcessError:
                messagebox.showerror("Lỗi", f"Không thể gỡ chặn {ip}. Có thể IP này không bị chặn hoặc Jail sai.")

    def view_log(self):
        """Xem log fail2ban"""
        log_path = "/var/log/fail2ban.log"
        if os.path.exists(log_path):
            win = tk.Toplevel(self.parent)
            win.title("Fail2Ban Log")
            text = tk.Text(win, wrap=tk.WORD)
            text.pack(fill=tk.BOTH, expand=True)
            try:
                with open(log_path, 'r') as f:
                    # Đọc 2000 ký tự cuối
                    f.seek(0, 2)
                    size = f.tell()
                    f.seek(max(size - 5000, 0), 0)
                    content = f.read()
                    text.insert(tk.END, content)
            except Exception as e:
                text.insert(tk.END, f"Lỗi đọc log: {e}")
