#!/usr/bin/env python3
import subprocess
import time
import logging
from collections import defaultdict
import json
import os
import sys

# --- CẤU HÌNH ---
CONFIG_FILE = '/etc/firewall_auto_block.json'
LOG_FILE = '/var/log/firewall_auto_block.log'
ALERT_FILE = '/var/log/firewall_alerts.json'

# Logging ra màn hình và file
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
        self.config = self.load_config()
        self.sync_blocked_ips_from_system()

    def load_config(self):
        default_config = {
            'check_interval': 5,
            'syn_threshold': 50,      # Ngưỡng SYN (TCP)
            'conn_threshold': 100,    # Ngưỡng Kết nối (Slowloris)
            'udp_threshold': 100,     # [MỚI] Ngưỡng UDP Flood
            'ban_time': 300,          # Thời gian chặn (giây)
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
        """Đồng bộ IP đã chặn từ iptables để không chặn lại"""
        try:
            result = subprocess.run(['iptables', '-L', 'INPUT', '-n'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                parts = line.split()
                # Dòng chặn thường có dạng: DROP all -- 1.2.3.4 0.0.0.0/0
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

    def get_tcp_stats(self):
        """Đếm kết nối TCP (SYN và ESTABLISHED) dùng lệnh ss"""
        syn_stats = defaultdict(int)
        conn_stats = defaultdict(int)
        whitelist = self.config.get('whitelist', [])

        try:
            # Lấy tất cả socket TCP (-t) dạng số (-n)
            # Dùng -a để lấy cả đang chờ kết nối, dùng state để lọc
            # Cách tối ưu: Lấy SYN-RECV
            res_syn = subprocess.run(['ss', '-nt', 'state', 'syn-recv'], capture_output=True, text=True)
            for line in res_syn.stdout.splitlines()[1:]:
                self._parse_ss_line(line, syn_stats, whitelist)

            # Lấy ESTABLISHED
            res_est = subprocess.run(['ss', '-nt', 'state', 'established'], capture_output=True, text=True)
            for line in res_est.stdout.splitlines()[1:]:
                self._parse_ss_line(line, conn_stats, whitelist)
                
        except Exception as e:
            logging.error(f"Lỗi TCP Check: {e}")
        return syn_stats, conn_stats

    def _parse_ss_line(self, line, stats_dict, whitelist):
        parts = line.split()
        try:
            # ss output: State Recv-Q Send-Q Local:Port Peer:Port
            peer_idx = 4 if len(parts) > 4 else 3 
            peer_str = parts[peer_idx]
            if ':' in peer_str:
                if ']' in peer_str: ip = peer_str.split(']')[0].replace('[', '') # IPv6
                else: ip = peer_str.split(':')[0] # IPv4
                
                if self.is_valid_ip(ip) and ip not in whitelist:
                    stats_dict[ip] += 1
        except: pass

    def get_udp_stats(self):
        """[MỚI] Đếm luồng UDP dùng conntrack"""
        udp_stats = defaultdict(int)
        whitelist = self.config.get('whitelist', [])
        
        try:
            # Yêu cầu cài đặt: sudo apt install conntrack
            # Lấy danh sách kết nối UDP, giới hạn 5000 dòng để tránh treo máy khi flood nặng
            cmd = "conntrack -L -p udp 2>/dev/null | head -n 5000"
            output = subprocess.check_output(cmd, shell=True, text=True)
            
            for line in output.splitlines():
                # Format: udp 17 29 src=1.2.3.4 dst=...
                if 'src=' in line:
                    parts = line.split()
                    for p in parts:
                        if p.startswith('src='):
                            ip = p.split('=')[1]
                            if self.is_valid_ip(ip) and ip not in whitelist:
                                udp_stats[ip] += 1
                            break # Chỉ lấy src đầu tiên (nguồn gửi)
        except subprocess.CalledProcessError:
            # Nếu chưa cài conntrack hoặc lỗi
            pass 
        except Exception as e:
            logging.error(f"Lỗi UDP Check: {e}")
            
        return udp_stats

    def check_for_attacks(self, syn_stats, conn_stats, udp_stats):
        syn_thresh = int(self.config.get('syn_threshold', 50))
        conn_thresh = int(self.config.get('conn_threshold', 100))
        udp_thresh = int(self.config.get('udp_threshold', 100))

        # --- DEBUG NHẸ ---
        total_udp = sum(udp_stats.values())
        if total_udp > 10: # Chỉ hiện khi có traffic UDP đáng kể
            print(f"--- INFO: Phát hiện {total_udp} luồng UDP ---")

        # 1. Chặn SYN Flood
        for ip, count in syn_stats.items():
            if count > syn_thresh and ip not in self.banned_ips:
                self.block_ip(ip, f"SYN Flood ({count} > {syn_thresh})")

        # 2. Chặn Conn Flood (Slowloris)
        for ip, count in conn_stats.items():
            if count > conn_thresh and ip not in self.banned_ips:
                self.block_ip(ip, f"Conn Flood ({count} > {conn_thresh})")

        # 3. Chặn UDP Flood [MỚI]
        for ip, count in udp_stats.items():
            if count > udp_thresh and ip not in self.banned_ips:
                self.block_ip(ip, f"UDP Flood ({count} > {udp_thresh})")

    def block_ip(self, ip, reason):
        try:
            # Check kỹ lại trước khi chặn
            check = subprocess.run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'], capture_output=True)
            if check.returncode != 0:
                subprocess.run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'], check=True)
                
                # Cắt kết nối UDP hiện tại của IP đó ngay lập tức (Xóa khỏi conntrack)
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
            alerts = alerts[-100:] # Giữ 100 log mới nhất
            
            with open(ALERT_FILE, 'w') as f:
                json.dump(alerts, f, indent=2)
        except Exception: pass

    def run(self):
        logging.info("Firewall Monitor V2.0 (TCP + UDP) Started...")
        print("Đang chạy... Nhấn Ctrl+C để dừng.")
        while True:
            try:
                self.config = self.load_config()
                
                # Lấy thống kê từ 3 nguồn
                syn, conn = self.get_tcp_stats()
                udp = self.get_udp_stats()
                
                # Kiểm tra tấn công
                self.check_for_attacks(syn, conn, udp)
                
                # Dọn dẹp IP cũ
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
    
    # Kiểm tra xem conntrack đã cài chưa
    if subprocess.run("which conntrack", shell=True, stdout=subprocess.DEVNULL).returncode != 0:
        print("CẢNH BÁO: Chưa cài đặt 'conntrack'. Tính năng chặn UDP sẽ không hoạt động.")
        print("Vui lòng chạy: sudo apt-get install conntrack")
        time.sleep(3)

    app = DosDetector()
    app.run()
