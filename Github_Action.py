import re, json, time, base64, requests, hmac, struct, imaplib, os
from bs4 import BeautifulSoup

# --- 从你的 .yml 环境变量中读取配置 ---
USERNAME = os.getenv('EUSERV_USERNAME', '')
PASSWORD = os.getenv('EUSERV_PASSWORD', '')
EUSERV_2FA_SECRET = os.getenv('EUSERV_2FA_SECRET', '')
# 提醒：请确保在 GitHub Secrets 补充了下面这两个变量
GMAIL_USER = os.getenv('GMAIL_USER', '')
GMAIL_PASS = os.getenv('GMAIL_PASS', '')

def log(info):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {info}")

# --- 核心：生成 2FA 动态验证码 ---
def get_totp(key):
    try:
        key = base64.b32decode(key.upper().replace(' ', '') + '=' * ((8 - len(key.replace(' ', ''))) % 8))
        counter = struct.pack('>Q', int(time.time() / 30))
        mac = hmac.new(key, counter, 'sha1').digest()
        offset = mac[-1] & 0x0f
        binary = struct.unpack('>L', mac[offset:offset+4])[0] & 0x7fffffff
        return str(binary)[-6:].zfill(6)
    except Exception as e:
        log(f"2FA 计算失败，请检查密钥格式: {e}")
        return None

# --- 核心：从 Gmail 自动抓取 EUserv 发来的 PIN ---
def fetch_pin_from_gmail():
    log("正在从 Gmail 检索 EUserv 安全 PIN 码...")
    if not GMAIL_USER or not GMAIL_PASS:
        log("错误：未配置 GMAIL_USER 或 GMAIL_PASS 环境变量")
        return None
    
    for attempt in range(10):
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
            mail.login(GMAIL_USER, GMAIL_PASS)
            mail.select("inbox")
            # 搜索来自 EUserv 的未读或最新邮件
            status, data = mail.search(None, '(FROM "no-reply@euserv.com")')
            if status == 'OK' and data[0]:
                latest_id = data[0].split()[-1]
                _, msg_data = mail.fetch(latest_id, "(RFC822)")
                content = msg_data[0][1].decode('utf-8', errors='ignore')
                pin_match = re.search(r'PIN:[\s\n]*(\d{6})', content)
                if pin_match:
                    pin = pin_match.group(1)
                    log(f"成功抓取到最新 PIN: {pin}")
                    mail.logout()
                    return pin
            mail.logout()
        except Exception as e:
            log(f"Gmail 连接中... ({e})")
        time.sleep(15) # 邮件发送有延迟，每 15 秒查一次
    return None

def main_handler():
    if not USERNAME or not PASSWORD:
        log("错误：未读取到 EUserv 账号或密码，请检查 GitHub Secrets 命名。")
        return

    session = requests.Session()
    session.headers.update({"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
    
    # 1. 访问登录页获取 Session ID
    url = "https://support.euserv.com/index.iphp"
    resp = session.get(url)
    try:
        sess_id = re.findall("PHPSESSID=(\\w+);", str(resp.headers))[0]
    except:
        log("无法获取 Session ID，可能是 EUserv 官网限制。")
        return

    # 2. 提交第一步登录
    log(f"正在登录账户: {USERNAME}")
    login_data = {"email": USERNAME, "password": PASSWORD, "subaction": "login", "sess_id": sess_id}
    f = session.post(url, data=login_data)
    
    # 3. 处理 2FA 验证
    if "authenticator app" in f.text:
        log("检测到 2FA，正在生成并提交动态码...")
        two_fa_code = get_totp(EUSERV_2FA_SECRET)
        soup = BeautifulSoup(f.text, "html.parser")
        hidden_inputs = {inp["name"]: inp.get("value", "") for inp in soup.find_all("input", type="hidden")}
        hidden_inputs["pin"] = two_fa_code
        f = session.post(url, data=hidden_inputs)

    if "Hello" not in f.text and "customer data" not in f.text:
        log("登录最终失败，请检查账号、密码或 2FA 密钥。")
        return

    log("登录成功！正在检索可续期订单...")
    # 4. 提取所有订单 ID 并尝试续期
    orders = list(set(re.findall(r'ord_no=(\d+)', f.text)))
    if not orders:
        log("未发现有效订单。")
        return

    for oid in orders:
        log(f"处理订单: {oid} ...")
        # 触发 EUserv 发送 PIN 邮件
        session.post(url, data={"sess_id": sess_id, "subaction": "show_kc2_security_password_dialog", "prefix": "kc2_customer_contract_details_extend_contract_", "type": "1"})
        
        pin = fetch_pin_from_gmail()
        if pin:
            # 提交 PIN 获取 Token
            res = session.post(url, data={"auth": pin, "sess_id": sess_id, "subaction": "kc2_security_password_get_token", "prefix": "kc2_customer_contract_details_extend_contract_", "type": 1, "ident": f"kc2_customer_contract_details_extend_contract_{oid}"})
            try:
                token = json.loads(res.text).get("token", {}).get("value")
                if token:
                    # 最终执行续期动作
                    session.post(url, data={"sess_id": sess_id, "ord_id": oid, "subaction": "kc2_customer_contract_details_extend_contract_term", "token": token})
                    log(f"🎉 订单 {oid} 续期任务已成功提交！")
            except:
                log(f"订单 {oid} 获取 Token 失败，可能已续期过。")
        else:
            log(f"❌ 未能获取到邮件 PIN，订单 {oid} 跳过。")

if __name__ == "__main__":
    main_handler()
