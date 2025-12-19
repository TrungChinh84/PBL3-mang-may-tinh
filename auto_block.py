#!/usr/bin/env python3
import subprocess
import time
import logging
from collections import defaultdict, deque
import json
import os
import sys

# --- CẤU HÌNH ---
CONFIG_FILE = '/etc/firewall_auto_block.json'
LOG_FILE = '/var/log/firewall_auto_block.log'
ALERT_FILE = '/var/log/firewall_alerts.json'

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout) # In cả ra màn hình terminal
    ]
)

class DosDetector:
    def __init__(self):
        self.banned_ips = {}
        self.config = self.load_config()
        self.sync_blocked_ips_from_system()

    def load_config(self):
        default_config = {
            'check_interval': 5,      # Giảm xuống 5s để test cho nhanh
            'syn_threshold': 20,      # Giảm xuống 20 để dễ kích hoạt khi test
            'conn_threshold': 50,     # Giảm xuống 50
            'ban_time': 300,          # Ban 5 phút
            'whitelist': ['127.0.0.1']
        }
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    # Merge config để tránh lỗi thiếu key
                    default_config.update(data)
                    return default_config
            except Exception as e:
                logging.error(f"Lỗi đọc config: {e}")
        return default_config

    def sync_blocked_ips_from_system(self):
        """Đồng bộ IP đã chặn từ trước"""
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
        # Xử lý trường hợp IPv6 map IPv4 (ví dụ ::ffff:192.168.1.1)
        if ip.startswith('::ffff:'):
            ip = ip.replace('::ffff:', '')
        
        parts = ip.split('.')
        if len(parts) != 4: return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError: return False

    def get_network_stats(self):
        syn_stats = defaultdict(int)
        conn_stats = defaultdict(int)
        whitelist = self.config.get('whitelist', [])

        # Hàm phụ để parse dòng output của ss
        def parse_ss_line(line, stats_dict):
            parts = line.split()
            # ss output: State Recv-Q Send-Q Local_Addr:Port Peer_Addr:Port
            # Peer thường ở index 4 (cột 5), nhưng đôi khi index 3 nếu dính liền
            try:
                if len(parts) < 4: return
                
                # Tìm phần tử chứa Peer Address (thường có dấu :)
                peer_str = parts[4] if len(parts) > 4 else parts[3]
                
                if ':' in peer_str:
                    # Tách IP khỏi Port (xử lý cả IPv6 [...] và IPv4)
                    if ']' in peer_str: # IPv6
                        ip = peer_str.split(']')[0].replace('[', '')
                    else: # IPv4
                        ip = peer_str.split(':')[0]
                    
                    if self.is_valid_ip(ip) and ip not in whitelist:
                        stats_dict[ip] += 1
            except Exception:
                pass

        try:
            # 1. Check SYN-RECV
            res_syn = subprocess.run(['ss', '-nt', 'state', 'syn-recv'], capture_output=True, text=True)
            for line in res_syn.stdout.splitlines()[1:]:
                parse_ss_line(line, syn_stats)

            # 2. Check ESTABLISHED
            res_est = subprocess.run(['ss', '-nt', 'state', 'established'], capture_output=True, text=True)
            for line in res_est.stdout.splitlines()[1:]:
                parse_ss_line(line, conn_stats)

        except Exception as e:
            logging.error(f"Lỗi ss: {e}")

        return syn_stats, conn_stats

    def check_for_attacks(self, syn_stats, conn_stats):
        syn_thresh = int(self.config.get('syn_threshold', 50))
        conn_thresh = int(self.config.get('conn_threshold', 100))

        # --- DEBUG LOGGING: Quan trọng để biết code có chạy không ---
        total_syn = sum(syn_stats.values())
        total_conn = sum(conn_stats.values())
        if total_syn > 0 or total_conn > 0:
            print(f"--- DEBUG: Đang theo dõi {total_syn} SYN, {total_conn} ESTABLISHED ---")
            for ip, count in syn_stats.items():
                print(f"   > IP {ip}: {count} SYN (Ngưỡng: {syn_thresh})")
        # ------------------------------------------------------------

        for ip, count in syn_stats.items():
            if count > syn_thresh and ip not in self.banned_ips:
                self.block_ip(ip, f"SYN Flood: {count} > {syn_thresh}")

        for ip, count in conn_stats.items():
            if count > conn_thresh and ip not in self.banned_ips:
                self.block_ip(ip, f"Conn Flood: {count} > {conn_thresh}")

    def block_ip(self, ip, reason):
        try:
            # Check kỹ lại xem đã tồn tại trong iptables chưa để tránh lỗi
            check = subprocess.run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'], capture_output=True)
            if check.returncode != 0:
                subprocess.run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'], check=True)
                logging.warning(f"ĐÃ CHẶN IP: {ip} - Lý do: {reason}")
                
                self.banned_ips[ip] = time.time()
                self.write_alert({
                    'timestamp': time.time(),
                    'ip': ip,
                    'reason': reason,
                    'action': 'BLOCKED'
                })
            else:
                print(f"IP {ip} đã bị chặn từ trước.")
                self.banned_ips[ip] = time.time()

        except Exception as e:
            logging.error(f"Lỗi khi chặn {ip}: {e}")

    def unban_old_ips(self):
        ban_time = int(self.config.get('ban_time', 0))
        if ban_time <= 0: return

        current_time = time.time()
        # Tạo list copy để tránh lỗi runtime khi delete dictionary
        for ip, blocked_time in list(self.banned_ips.items()):
            if current_time - blocked_time > ban_time:
                try:
                    subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                    logging.info(f"GỠ BỎ CHẶN {ip} (Hết hạn)")
                    del self.banned_ips[ip]
                    
                    self.write_alert({
                        'timestamp': time.time(),
                        'ip': ip,
                        'reason': 'Expired',
                        'action': 'UNBANNED'
                    })
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
            if len(alerts) > 100: alerts = alerts[-100:] # Giữ 100 log mới nhất
            
            with open(ALERT_FILE, 'w') as f:
                json.dump(alerts, f, indent=2)
        except Exception as e:
            logging.error(f"Lỗi ghi JSON: {e}")

    def run(self):
        logging.info("Auto-Block Service started...")
        print("Đang chạy... Nhấn Ctrl+C để dừng.")
        while True:
            try:
                self.config = self.load_config()
                syn, conn = self.get_network_stats()
                self.check_for_attacks(syn, conn)
                self.unban_old_ips()
                
                # Sleep theo config
                time.sleep(self.config.get('check_interval', 5))
            except KeyboardInterrupt:
                break
            except Exception as e:
                logging.error(f"Lỗi main loop: {e}")
                time.sleep(5)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Cần chạy với quyền ROOT (sudo)!")
        sys.exit(1)
    
    app = DosDetector()
    app.run()
