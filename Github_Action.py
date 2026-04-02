import re, json, time, base64, requests, hmac, struct, imaplib, os
from bs4 import BeautifulSoup

# --- 变量读取 (精准对齐你的 Secrets 命名) ---
USERNAME = os.getenv('EU_USERNAME', '')
PASSWORD = os.getenv('EU_PASSWORD', '')
EUSERV_2FA_SECRET = os.getenv('EU_2FA_SECRET', '')
GMAIL_USER = os.getenv('GMAIL_USER', '')
GMAIL_PASS = os.getenv('GMAIL_PASS', '')

def log(info):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {info}")

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
    log("正在从 Gmail 检索续期 PIN 码...")
    if not GMAIL_USER or not GMAIL_PASS:
        log("❌ 错误：未配置 GMAIL_USER 或 GMAIL_PASS")
        return None
    for i in range(12): # 尝试 4 分钟
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
                    log(f"✅ 成功获取邮件 PIN: {pin_match.group(1)}")
                    mail.logout()
                    return pin_match.group(1)
            mail.logout()
        except Exception as e:
            log(f"Gmail 检索中... ({i+1}/12)")
        time.sleep(20)
    return None

def main_handler():
    log("=== 启动环境检查 ===")
    if not USERNAME or not PASSWORD:
        log("❌ 错误：环境变量读取失败。请检查 GitHub Secrets 和 yml 文件。")
        return
    log(f"账号长度: {len(USERNAME)} | 密码长度: {len(PASSWORD)} | 2FA密钥长度: {len(EUSERV_2FA_SECRET)}")

    session = requests.Session()
    session.headers.update({"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
    url = "https://support.euserv.com/index.iphp"
    
    try:
        resp = session.get(url, timeout=30)
        sess_id = re.findall("PHPSESSID=(\\w+);", str(resp.headers))[0]
    except:
        log("❌ 无法建立会话，请稍后重试。")
        return

    log(f"正在尝试第一阶段登录: {USERNAME[:3]}***")
    login_data = {"email": USERNAME, "password": PASSWORD, "subaction": "login", "sess_id": sess_id}
    f = session.post(url, data=login_data)
    
    # --- 登录结果诊断 ---
    if "authenticator app" in f.text:
        log("🎯 发现 2FA 验证，启动时间容错尝试...")
        soup = BeautifulSoup(f.text, "html.parser")
        hidden = {inp["name"]: inp.get("value", "") for inp in soup.find_all("input", type="hidden")}
        
        success = False
        current_step = int(time.time() / 30)
        for offset in [0, -1, 1]:
            code = get_totp(EUSERV_2FA_SECRET, current_step + offset)
            hidden["pin"] = code
            log(f"尝试 2FA 码: {code} (偏移: {offset*30}s)")
            f_2fa = session.post(url, data=hidden)
            if "Hello" in f_2fa.text or "customer data" in f_2fa.text:
                log("✅ 2FA 验证成功！")
                f = f_2fa
                success = True
                break
        if not success:
            log("❌ 2FA 验证全部失败。请确认 Secrets 里的密钥是 16 位字符而非 6 位数字。")
            return
            
    elif "not correct" in f.text or "Invalid" in f.text:
        log("❌ 官网返回：账号或密码错误。请确认是 KC 号且密码无误。")
        return
    elif "Hello" not in f.text and "customer data" not in f.text:
        log(f"⚠️ 未知登录状态。页面摘要: {f.text[:100].replace(chr(10), '')}")
        return

    log("✅ 登录成功，开始检查订单...")
    orders = list(set(re.findall(r'ord_no=(\d+)', f.text)))
    if not orders:
        log("未发现任何订单。")
        return

    for oid in orders:
        log(f"📦 处理订单: {oid}")
        # 触发邮件发送
        session.post(url, data={"sess_id": sess_id, "subaction": "show_kc2_security_password_dialog", "prefix": "kc2_customer_contract_details_extend_contract_", "type": "1"})
        
        pin = fetch_pin_from_gmail()
        if pin:
            res = session.post(url, data={"auth": pin, "sess_id": sess_id, "subaction": "kc2_security_password_get_token", "prefix": "kc2_customer_contract_details_extend_contract_", "type": 1, "ident": f"kc2_customer_contract_details_extend_contract_{oid}"})
            try:
                token = json.loads(res.text).get("token", {}).get("value")
                if token:
                    session.post(url, data={"sess_id": sess_id, "ord_id": oid, "subaction": "kc2_customer_contract_details_extend_contract_term", "token": token})
                    log(f"🎉 订单 {oid} 续期任务提交成功！")
                else: log(f"订单 {oid} 未获取到 Token，可能已续期。")
            except: log(f"订单 {oid} 响应解析失败。")
        else: log(f"❌ 订单 {oid} 跳过（未收到邮件 PIN）。")

if __name__ == "__main__":
    main_handler()
