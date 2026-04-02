import re, json, time, base64, requests, hmac, struct, imaplib, os
from bs4 import BeautifulSoup

# --- 精准对齐你的 Secrets 命名 ---
USERNAME = os.getenv('EU_USERNAME', '')
PASSWORD = os.getenv('EU_PASSWORD', '')
EUSERV_2FA_SECRET = os.getenv('EU_2FA_SECRET', '')
GMAIL_USER = os.getenv('GMAIL_USER', '')
GMAIL_PASS = os.getenv('GMAIL_PASS', '')

def log(info):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {info}")

# --- 核心优化：支持指定时间戳生成 TOTP ---
def get_totp(key, time_step=None):
    try:
        if time_step is None:
            time_step = int(time.time() / 30)
        key = base64.b32decode(key.upper().replace(' ', '') + '=' * ((8 - len(key.replace(' ', ''))) % 8))
        counter = struct.pack('>Q', time_step)
        mac = hmac.new(key, counter, 'sha1').digest()
        offset = mac[-1] & 0x0f
        binary = struct.unpack('>L', mac[offset:offset+4])[0] & 0x7fffffff
        return str(binary)[-6:].zfill(6)
    except: return None

def fetch_pin_from_gmail():
    log("正在从 Gmail 检索 PIN 码...")
    if not GMAIL_USER or not GMAIL_PASS:
        log("错误：未配置 GMAIL 变量")
        return None
    for _ in range(10):
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
            mail.login(GMAIL_USER, GMAIL_PASS)
            mail.select("inbox")
            status, data = mail.search(None, '(FROM "no-reply@euserv.com")')
            if status == 'OK' and data[0]:
                latest_id = data[0].split()[-1]
                _, msg_data = mail.fetch(latest_id, "(RFC822)")
                content = msg_data[0][1].decode('utf-8', errors='ignore')
                pin_match = re.search(r'PIN:[\s\n]*(\d{6})', content)
                if pin_match:
                    mail.logout()
                    return pin_match.group(1)
            mail.logout()
        except: pass
        time.sleep(20)
    return None

def main_handler():
    if not USERNAME or not PASSWORD:
        log("错误：未读取到账号密码，请检查 .yml 文件设置。")
        return

    session = requests.Session()
    session.headers.update({"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
    url = "https://support.euserv.com/index.iphp"
    
    log(f"开始登录: {USERNAME}")
    resp = session.get(url)
    sess_id = re.findall("PHPSESSID=(\\w+);", str(resp.headers))[0]
    
    # 提交第一步登录
    f = session.post(url, data={"email": USERNAME, "password": PASSWORD, "subaction": "login", "sess_id": sess_id})
    
    # --- 核心优化：带容错的 2FA 登录 ---
    if "authenticator app" in f.text:
        log("检测到 2FA，正在尝试时间容错登录 (±30s)...")
        soup = BeautifulSoup(f.text, "html.parser")
        hidden_base = {inp["name"]: inp.get("value", "") for inp in soup.find_all("input", type="hidden")}
        
        success = False
        current_step = int(time.time() / 30)
        # 依次尝试：当前时间、前30秒、后30秒
        for step_offset in [0, -1, 1]:
            two_fa = get_totp(EUSERV_2FA_SECRET, current_step + step_offset)
            hidden_base["pin"] = two_fa
            log(f"尝试验证码: {two_fa}")
            f = session.post(url, data=hidden_base)
            if "Hello" in f.text or "customer data" in f.text:
                log("✅ 2FA 验证成功！")
                success = True
                break
            time.sleep(1)
        
        if not success:
            log("❌ 2FA 容错尝试全部失败。")
            return

    if "Hello" not in f.text and "customer data" not in f.text:
        log("登录最终失败，请检查账号密码。")
        return

    log("登录成功！寻找续期订单...")
    orders = list(set(re.findall(r'ord_no=(\d+)', f.text)))
    for oid in orders:
        log(f"处理订单: {oid}")
        session.post(url, data={"sess_id": sess_id, "subaction": "show_kc2_security_password_dialog", "prefix": "kc2_customer_contract_details_extend_contract_", "type": "1"})
        pin = fetch_pin_from_gmail()
        if pin:
            res = session.post(url, data={"auth": pin, "sess_id": sess_id, "subaction": "kc2_security_password_get_token", "prefix": "kc2_customer_contract_details_extend_contract_", "type": 1, "ident": f"kc2_customer_contract_details_extend_contract_{oid}"})
            try:
                token = json.loads(res.text).get("token", {}).get("value")
                if token:
                    session.post(url, data={"sess_id": sess_id, "ord_id": oid, "subaction": "kc2_customer_contract_details_extend_contract_term", "token": token})
                    log(f"🎉 订单 {oid} 续期成功！")
            except: pass
        else: log(f"❌ 订单 {oid} 获取 PIN 失败。")

if __name__ == "__main__":
    main_handler()
