#!/usr/bin/env python3
import subprocess
import time
import logging
from collections import defaultdict, deque
import json
import os
import sys
import math
import statistics

# --- CẤU HÌNH ---
CONFIG_FILE = '/etc/firewall_auto_block.json'
LOG_FILE = '/var/log/firewall_auto_block.log'
ALERT_FILE = '/var/log/firewall_alerts.json'

# --- CẤU HÌNH THUẬT TOÁN ---
HISTORY_LEN = 20        # Nhớ 20 mẫu gần nhất
MIN_SAMPLES = 5         # Cần ít nhất 5 mẫu để bắt đầu tính Z-Score
Z_THRESHOLD = 3.0       # Độ lệch chuẩn ( >3 là bất thường)
HARD_LIMIT_MULTIPLIER = 3 # Nếu vượt ngưỡng gấp 3 lần -> Chặn ngay không cần Z-Score

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

class DosDetector:
    def __init__(self):
        self.banned_ips = {}
        # Bộ nhớ lịch sử cho Z-Score
        self.syn_history = defaultdict(lambda: deque(maxlen=HISTORY_LEN))
        self.conn_history = defaultdict(lambda: deque(maxlen=HISTORY_LEN))
        self.udp_history = defaultdict(lambda: deque(maxlen=HISTORY_LEN))
        
        self.config = self.load_config()
        self.sync_blocked_ips_from_system()

    def load_config(self):
        default_config = {
            'check_interval': 5,
            'syn_threshold': 50,
            'conn_threshold': 100,
            'udp_threshold': 100,
            'ban_time': 300,
            'whitelist': ['127.0.0.1', '::1']
        }
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    default_config.update(data)
                    return default_config
            except Exception as e:
                logging.error(f"Lỗi đọc config: {e}")
        return default_config

    def sync_blocked_ips_from_system(self):
        try:
            result = subprocess.run(['iptables', '-L', 'INPUT', '-n'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 4 and parts[0] == 'DROP':
                    src_ip = parts[3]
                    if self.is_valid_ip(src_ip) and src_ip != '0.0.0.0/0':
                        self.banned_ips[src_ip] = time.time()
        except Exception:
            pass

    def is_valid_ip(self, ip):
        if not ip: return False
        if ip.startswith('::ffff:'): ip = ip.replace('::ffff:', '')
        parts = ip.split('.')
        if len(parts) != 4: return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError: return False

    # === CÁC HÀM TOÁN HỌC (MỚI) ===
    def calculate_z_score(self, history, current_val):
        """Tính độ lệch chuẩn Z-Score"""
        if len(history) < MIN_SAMPLES:
            return 0.0
        try:
            mean = statistics.mean(history)
            stdev = statistics.stdev(history)
            if stdev == 0: return 0.0
            return (current_val - mean) / stdev
        except:
            return 0.0

    def calculate_entropy(self, data_dict):
        """Tính Entropy để biết độ phân tán của cuộc tấn công"""
        # Nếu Entropy thấp -> Tập trung vào 1 vài IP (DoS)
        # Nếu Entropy cao -> Phân tán đều (DDoS hoặc Traffic sạch)
        values = list(data_dict.values())
        total = sum(values)
        if total == 0: return 0
        entropy = 0
        for x in values:
            if x > 0:
                p = x / total
                entropy -= p * math.log2(p)
        return entropy

    # === CÁC HÀM LẤY DỮ LIỆU (GIỮ NGUYÊN) ===
    def get_tcp_stats(self):
        syn_stats = defaultdict(int)
        conn_stats = defaultdict(int)
        whitelist = self.config.get('whitelist', [])
        try:
            res_syn = subprocess.run(['ss', '-nt', 'state', 'syn-recv'], capture_output=True, text=True)
            for line in res_syn.stdout.splitlines()[1:]:
                self._parse_ss_line(line, syn_stats, whitelist)

            res_est = subprocess.run(['ss', '-nt', 'state', 'established'], capture_output=True, text=True)
            for line in res_est.stdout.splitlines()[1:]:
                self._parse_ss_line(line, conn_stats, whitelist)
        except Exception as e:
            logging.error(f"Lỗi TCP Check: {e}")
        return syn_stats, conn_stats

    def _parse_ss_line(self, line, stats_dict, whitelist):
        parts = line.split()
        try:
            peer_idx = 4 if len(parts) > 4 else 3 
            peer_str = parts[peer_idx]
            if ':' in peer_str:
                if ']' in peer_str: ip = peer_str.split(']')[0].replace('[', '')
                else: ip = peer_str.split(':')[0]
                if self.is_valid_ip(ip) and ip not in whitelist:
                    stats_dict[ip] += 1
        except: pass

    def get_udp_stats(self):
        udp_stats = defaultdict(int)
        whitelist = self.config.get('whitelist', [])
        try:
            cmd = "conntrack -L -p udp 2>/dev/null | head -n 5000"
            output = subprocess.check_output(cmd, shell=True, text=True)
            for line in output.splitlines():
                if 'src=' in line:
                    parts = line.split()
                    for p in parts:
                        if p.startswith('src='):
                            ip = p.split('=')[1]
                            if self.is_valid_ip(ip) and ip not in whitelist:
                                udp_stats[ip] += 1
                            break 
        except: pass
        return udp_stats

    # === LOGIC CHẶN THÔNG MINH (UPDATED) ===
    def check_for_attacks(self, syn_stats, conn_stats, udp_stats):
        syn_thresh = int(self.config.get('syn_threshold', 50))
        conn_thresh = int(self.config.get('conn_threshold', 100))
        udp_thresh = int(self.config.get('udp_threshold', 100))

        # 1. Tính Entropy toàn cục (Để cảnh báo dạng tấn công)
        udp_entropy = self.calculate_entropy(udp_stats)
        if sum(udp_stats.values()) > 50 and udp_entropy < 1.0:
            logging.info(f"CẢNH BÁO: Entropy UDP thấp ({udp_entropy:.2f}) -> Dấu hiệu tấn công tập trung!")

        # 2. Kiểm tra từng loại tấn công với Z-Score
        self.analyze_and_block(syn_stats, self.syn_history, syn_thresh, "SYN Flood")
        self.analyze_and_block(conn_stats, self.conn_history, conn_thresh, "Conn Flood")
        self.analyze_and_block(udp_stats, self.udp_history, udp_thresh, "UDP Flood")

    def analyze_and_block(self, current_stats, history_store, threshold, attack_name):
        """Hàm xử lý chung cho cả TCP và UDP"""
        for ip, count in current_stats.items():
            # Thêm vào lịch sử để học
            history_store[ip].append(count)
            
            # Tính toán
            z_score = self.calculate_z_score(history_store[ip], count)
            
            # --- LOGIC QUYẾT ĐỊNH CHẶN ---
            should_block = False
            reason_detail = ""

            # Điều kiện 1: Tấn công quá mạnh (Gấp 3 lần ngưỡng) -> CHẶN NGAY
            if count > (threshold * HARD_LIMIT_MULTIPLIER):
                should_block = True
                reason_detail = f"{attack_name} (HARD LIMIT: {count} > {threshold*3})"

            # Điều kiện 2: Vượt ngưỡng VÀ Bất thường (Z-Score cao) -> CHẶN
            elif count > threshold and z_score > Z_THRESHOLD:
                should_block = True
                reason_detail = f"{attack_name} (Z-Score: {count} > {threshold}, Z={z_score:.2f})"

            # Debug nhẹ
            if count > threshold:
                print(f"[DEBUG] {ip}: Count={count}, Threshold={threshold}, Z={z_score:.2f} -> Block? {should_block}")

            if should_block and ip not in self.banned_ips:
                self.block_ip(ip, reason_detail)

    def block_ip(self, ip, reason):
        try:
            check = subprocess.run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'], capture_output=True)
            if check.returncode != 0:
                subprocess.run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'], check=True)
                
                if "UDP" in reason:
                    subprocess.run(f"conntrack -D -p udp -s {ip}", shell=True, stderr=subprocess.DEVNULL)

                logging.warning(f"ĐÃ CHẶN IP: {ip} - Lý do: {reason}")
                self.banned_ips[ip] = time.time()
                self.write_alert({
                    'timestamp': time.time(),
                    'ip': ip,
                    'reason': reason,
                    'action': 'BLOCKED'
                })
        except Exception as e:
            logging.error(f"Lỗi khi chặn {ip}: {e}")

    def unban_old_ips(self):
        ban_time = int(self.config.get('ban_time', 300))
        if ban_time <= 0: return
        current_time = time.time()
        for ip, blocked_time in list(self.banned_ips.items()):
            if current_time - blocked_time > ban_time:
                try:
                    subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                    logging.info(f"GỠ BỎ CHẶN {ip} (Hết hạn)")
                    del self.banned_ips[ip]
                    self.write_alert({'timestamp': time.time(), 'ip': ip, 'reason': 'Expired', 'action': 'UNBANNED'})
                except Exception:
                    del self.banned_ips[ip]

    def write_alert(self, alert_data):
        try:
            alerts = []
            if os.path.exists(ALERT_FILE):
                with open(ALERT_FILE, 'r') as f:
                    try: 
                        data = f.read().strip()
                        if data: alerts = json.loads(data)
                    except: pass
            
            if not isinstance(alerts, list): alerts = []
            alerts.append(alert_data)
            alerts = alerts[-100:] 
            
            with open(ALERT_FILE, 'w') as f:
                json.dump(alerts, f, indent=2)
        except Exception: pass

    def run(self):
        logging.info("Firewall Monitor (Hybrid: Threshold + Z-Score) Started...")
        print("Đang chạy... Nhấn Ctrl+C để dừng.")
        while True:
            try:
                self.config = self.load_config()
                syn, conn = self.get_tcp_stats()
                udp = self.get_udp_stats()
                
                self.check_for_attacks(syn, conn, udp)
                self.unban_old_ips()
                
                time.sleep(self.config.get('check_interval', 5))
            except KeyboardInterrupt:
                print("\nDừng chương trình.")
                break
            except Exception as e:
                logging.error(f"Lỗi main loop: {e}")
                time.sleep(5)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Cần chạy với quyền ROOT (sudo)!")
        sys.exit(1)
    
    if subprocess.run("which conntrack", shell=True, stdout=subprocess.DEVNULL).returncode != 0:
        print("CẢNH BÁO: Chưa cài đặt 'conntrack'. Tính năng chặn UDP sẽ không hoạt động.")
        time.sleep(3)

    app = DosDetector()
    app.run()
