#!/usr/bin/env python3
"""
Web Dashboard quản trị Firewall - PBL4
Chạy với quyền root: sudo python3 web_dashboard.py
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from functools import wraps
import subprocess
import json
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'PBL3_SUPER_SECRET_KEY' # Dùng để mã hóa session đăng nhập

# --- CẤU HÌNH PATH (Phải khớp với hệ thống của bạn) ---
ALERT_FILE = '/var/log/firewall_alerts.json'
CONFIG_FILE = '/etc/firewall_auto_block.json'
ADMIN_PASSWORD = 'admin123'  # Mật khẩu đăng nhập web

# --- DECORATOR KIỂM TRA ĐĂNG NHẬP ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

class FirewallManager:
    @staticmethod
    def is_valid_ip(ip):
        if not ip: return False
        parts = ip.split('.')
        if len(parts) != 4: return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError: return False

    @staticmethod
    def get_iptables_rules():
        try:
            result = subprocess.run(['iptables', '-L', 'INPUT', '-n', '--line-numbers'], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def block_ip(ip):
        try:
            subprocess.run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'], check=True)
            return True, f"Đã chặn IP {ip}"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def unblock_ip(ip):
        try:
            subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            return True, f"Đã gỡ chặn IP {ip}"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_stats():
        alerts = []
        blocked_count = 0
        try:
            # Đếm số dòng DROP trong iptables
            res = subprocess.run("iptables -L INPUT -n | grep DROP | wc -l", shell=True, capture_output=True, text=True)
            blocked_count = int(res.stdout.strip())

            # Đọc alerts
            if os.path.exists(ALERT_FILE):
                with open(ALERT_FILE, 'r') as f:
                    alerts = json.load(f)
                    if isinstance(alerts, list):
                        alerts.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
                        alerts = alerts[:20] # Lấy 20 cái mới nhất
        except: pass
        return blocked_count, alerts

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['password'] == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            error = 'Sai mật khẩu!'
    return render_template('login.html', error=error) if os.path.exists('templates/login.html') else f"""
    <form method=post>
        <input type=password name=password placeholder='Nhập mật khẩu (admin123)'>
        <input type=submit value=Login>
        <p style='color:red'>{error or ''}</p>
    </form>
    """

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/status')
@login_required
def api_status():
    blocked_count, alerts = FirewallManager.get_stats()
    
    # Đọc trạng thái service
    service_status = "STOPPED"
    try:
        res = subprocess.run(['systemctl', 'is-active', 'firewall-auto-block'], capture_output=True, text=True)
        service_status = res.stdout.strip().upper()
    except: pass

    return jsonify({
        'blocked_count': blocked_count,
        'alerts': alerts,
        'service_status': service_status,
        'updated_at': datetime.now().strftime("%H:%M:%S")
    })

@app.route('/api/action', methods=['POST'])
@login_required
def api_action():
    data = request.json
    action = data.get('type')
    ip = data.get('ip', '').strip()

    if action == 'toggle_service':
        # Bật tắt service auto-block
        current = data.get('current_status')
        cmd = 'stop' if current == 'ACTIVE' else 'start'
        os.system(f"systemctl {cmd} firewall-auto-block")
        return jsonify({'success': True, 'message': f"Đã gửi lệnh {cmd} service"})

    if not FirewallManager.is_valid_ip(ip):
        return jsonify({'success': False, 'message': 'IP không hợp lệ'})

    if action == 'block':
        success, msg = FirewallManager.block_ip(ip)
    elif action == 'unblock':
        success, msg = FirewallManager.unblock_ip(ip)
    else:
        return jsonify({'success': False, 'message': 'Hành động không rõ'})

    return jsonify({'success': success, 'message': msg})

@app.route('/api/config', methods=['GET', 'POST'])
@login_required
def api_config():
    """Đọc và Ghi file config JSON"""
    if request.method == 'GET':
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return jsonify(json.load(f))
        return jsonify({}) # Trả về rỗng nếu chưa có file

    if request.method == 'POST':
        try:
            new_config = request.json
            with open(CONFIG_FILE, 'w') as f:
                json.dump(new_config, f, indent=4)
            return jsonify({'success': True, 'message': 'Đã lưu cấu hình!'})
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)})

@app.route('/api/rules')
@login_required
def api_rules():
    return jsonify({'rules': FirewallManager.get_iptables_rules()})

if __name__ == '__main__':
    # SSL context='adhoc' để chạy HTTPS nếu cần, nhưng chạy local HTTP cho dễ
    if os.geteuid() != 0:
        print("Vui lòng chạy với quyền ROOT (sudo)")
    else:
        app.run(host='0.0.0.0', port=5000, debug=True)
