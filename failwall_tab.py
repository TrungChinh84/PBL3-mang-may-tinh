import tkinter as tk
from tkinter import ttk, messagebox
import subprocess

class FirewallTab:
    def __init__(self, parent):
        self.parent = parent
        
        # --- Khung chứa chính ---
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- Thanh công cụ (Buttons) ---
        self.toolbar = ttk.Frame(self.frame)
        self.toolbar.pack(fill=tk.X, pady=5)

        ttk.Button(self.toolbar, text="Làm Mới (Refresh)", command=self.load_rules).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.toolbar, text="Thêm Rule Mới", command=self.open_add_rule_window).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.toolbar, text="Xóa Rule Đã Chọn", command=self.delete_rule).pack(side=tk.LEFT, padx=5)
        
        # --- Bảng hiển thị (Treeview) ---
        columns = ("chain", "num", "target", "prot", "opt", "source", "destination", "options")
        self.tree = ttk.Treeview(self.frame, columns=columns, show='headings', height=20)
        
        # Định nghĩa tiêu đề cột
        self.tree.heading("chain", text="Chain")
        self.tree.heading("num", text="No.")
        self.tree.heading("target", text="Hành Động") # ACCEPT/DROP
        self.tree.heading("prot", text="Giao Thức")
        self.tree.heading("opt", text="Opt")
        self.tree.heading("source", text="Nguồn (Source)")
        self.tree.heading("destination", text="Đích (Dest)")
        self.tree.heading("options", text="Thông tin thêm (Ports...)")

        # Căn chỉnh cột
        self.tree.column("chain", width=80, anchor=tk.CENTER)
        self.tree.column("num", width=50, anchor=tk.CENTER)
        self.tree.column("target", width=80, anchor=tk.CENTER)
        self.tree.column("prot", width=60, anchor=tk.CENTER)
        self.tree.column("opt", width=50, anchor=tk.CENTER)
        self.tree.column("source", width=120)
        self.tree.column("destination", width=120)
        self.tree.column("options", width=200)

        # Scrollbar
        scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Load dữ liệu lần đầu
        self.load_rules()

    def load_rules(self):
        """Đọc quy tắc từ iptables và hiển thị lên bảng"""
        # Xóa dữ liệu cũ
        for item in self.tree.get_children():
            self.tree.delete(item)

        try:
            # Lệnh: iptables -L -n --line-numbers (Liệt kê số dòng để dễ xóa)
            result = subprocess.run(['iptables', '-L', '-n', '--line-numbers'], capture_output=True, text=True)
            output = result.stdout.splitlines()

            current_chain = ""
            for line in output:
                line = line.strip()
                if not line: continue
                
                # Phát hiện Chain (Ví dụ: Chain INPUT (policy ACCEPT))
                if line.startswith("Chain"):
                    current_chain = line.split()[1]
                    continue
                
                # Bỏ qua dòng tiêu đề của iptables (num target prot...)
                if line.startswith("num"):
                    continue

                # Xử lý dòng rule
                # Cấu trúc: num target prot opt source destination options
                parts = line.split(maxsplit=6) # Tách tối đa 6 khoảng trắng đầu
                if len(parts) >= 6:
                    num = parts[0]
                    target = parts[1]
                    prot = parts[2]
                    opt = parts[3]
                    source = parts[4]
                    dest = parts[5]
                    options = parts[6] if len(parts) > 6 else ""
                    
                    self.tree.insert("", tk.END, values=(current_chain, num, target, prot, opt, source, dest, options))

        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể lấy danh sách iptables: {e}")

    def delete_rule(self):
        """Xóa rule đang được chọn"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn một dòng để xóa!")
            return

        item_data = self.tree.item(selected_item)
        values = item_data['values']
        chain = values[0]
        num = values[1]

        confirm = messagebox.askyesno("Xác nhận", f"Bạn có chắc muốn xóa Rule #{num} trong Chain {chain}?")
        if confirm:
            try:
                # Lệnh xóa: iptables -D CHAIN NUM
                subprocess.run(['iptables', '-D', chain, str(num)], check=True)
                messagebox.showinfo("Thành công", "Đã xóa quy tắc!")
                self.load_rules() # Reload lại bảng
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Lỗi", f"Không thể xóa quy tắc: {e}")

    def open_add_rule_window(self):
        """Mở cửa sổ popup để thêm rule mới"""
        win = tk.Toplevel(self.parent)
        win.title("Thêm Quy Tắc Mới")
        win.geometry("400x350")

        # --- Form nhập liệu ---
        ttk.Label(win, text="Chain:").grid(row=0, column=0, padx=10, pady=5, sticky='w')
        chain_cb = ttk.Combobox(win, values=["INPUT", "OUTPUT", "FORWARD"], state="readonly")
        chain_cb.current(0) # Mặc định INPUT
        chain_cb.grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(win, text="Hành động (Action):").grid(row=1, column=0, padx=10, pady=5, sticky='w')
        action_cb = ttk.Combobox(win, values=["DROP", "ACCEPT", "REJECT"], state="readonly")
        action_cb.current(0) # Mặc định DROP
        action_cb.grid(row=1, column=1, padx=10, pady=5)

        ttk.Label(win, text="Giao thức (Protocol):").grid(row=2, column=0, padx=10, pady=5, sticky='w')
        prot_cb = ttk.Combobox(win, values=["tcp", "udp", "icmp", "all"])
        prot_cb.current(0)
        prot_cb.grid(row=2, column=1, padx=10, pady=5)

        ttk.Label(win, text="IP Nguồn (Source IP):").grid(row=3, column=0, padx=10, pady=5, sticky='w')
        src_entry = ttk.Entry(win)
        src_entry.grid(row=3, column=1, padx=10, pady=5)
        ttk.Label(win, text="(Để trống = Tất cả)").grid(row=3, column=2, padx=5, sticky='w')

        ttk.Label(win, text="Cổng Đích (Dest Port):").grid(row=4, column=0, padx=10, pady=5, sticky='w')
        port_entry = ttk.Entry(win)
        port_entry.grid(row=4, column=1, padx=10, pady=5)
        ttk.Label(win, text="(VD: 80, 22)").grid(row=4, column=2, padx=5, sticky='w')

        # Hàm xử lý nút Lưu
        def save_rule():
            chain = chain_cb.get()
            action = action_cb.get()
            prot = prot_cb.get()
            src_ip = src_entry.get().strip()
            port = port_entry.get().strip()

            # Xây dựng lệnh iptables
            # iptables -A INPUT -p tcp -s 192.168.1.5 --dport 80 -j DROP
            cmd = ['iptables', '-A', chain]
            
            if prot != 'all':
                cmd.extend(['-p', prot])
            
            if src_ip:
                cmd.extend(['-s', src_ip])
            
            if port:
                # Cổng chỉ áp dụng cho tcp/udp
                if prot in ['tcp', 'udp']:
                    cmd.extend(['--dport', port])
                else:
                    messagebox.showwarning("Lỗi logic", "Chỉ định Port yêu cầu giao thức là TCP hoặc UDP")
                    return

            cmd.extend(['-j', action])

            try:
                subprocess.run(cmd, check=True)
                messagebox.showinfo("Thành công", f"Đã thêm quy tắc vào {chain}")
                self.load_rules() # Reload bảng chính
                win.destroy() # Đóng popup
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Lỗi thực thi", f"Không thể thêm rule:\n{e}")

        ttk.Button(win, text="Thêm Rule", command=save_rule).grid(row=5, column=0, columnspan=2, pady=20)
