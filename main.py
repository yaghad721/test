import sys
import subprocess
import io
import os
import time
import sqlite3
import requests
import copy
import json

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from mitmproxy import http
from common.utils import aes_decrypt, encrypt_api, get_available_room, CrEaTe_ProTo

# ==================== CONFIG ====================
LISTEN_PORT = 9944
UID_FILE = "uid.txt"
WHITELIST_MSG = "[ffffff] UID NOT AUTHORIZED\n\n[FFFFFF]UID: {uid} ."

FIREBASE_DATABASE_URL = "https://axc-corp-default-rtdb.asia-southeast1.firebasedatabase.app/users.json"
DB_FILE = "bot_data.db"

# ==================== MOBILE PROTO ====================
MOBILE_PROTO = "25f16c42b17c8239fccb04095cf57404c3b0bb26906e7ba86f20ce787935f3b9eea0e0cf108b16269a322d06d9cadf6b4e6822d26490eb78ac78ea85705321894d288f6517b2a17b6027ebfd00ed9b336a2ec1c6bed513c218e0bb142bbc045782b578328fe0cea774f6e60f3e278794110dc58ed62a87948fc4005882a1ac2a10d18762c6789d2c148d1924b3e04eff87b8538dfc5f8bfe8ff503dc2849f2343fa13bb892005d68bad712508475f1735869b65b24a48f96c95937794363497b7897600cf8786407d6d8bc01d87eaee4a00da554fc96b6f415119e29efe1fe491c244edcc3091e5a2148954e870a3a1c5cddcf022ca8453a030013b4f2a8dd18d8e5e5be88c04cab6c0933d96bcc44600f619b424e89f95f979b46f457e51d6742a4398ca4c8d4b9f5a3e8c9c3c08363bfcd8d072518973c099abf69958e130b027f36dc007d449e544037f61a21fbd7735c2014028c3d29ccefcf3a25f2a65bd574f75a8ac8325106b75155ede5ee1919fbc12b3d86f34e564f3728cdf8165d399f1de23a2cee57ec283d36e1525d2392cbcffd5a3bf7766867eda25720864aeb06c729bc9fe254059376fcd70e4879ea6f77355948843585e6380c220793065084ecb64a8596183815c297d5bf878927a5205c57601ea87bbf7451d3c4d83ffdaec2f891e9da8959cfc5a655c5be056712538eee05518dfa80072a4c27d2203c2fd3c5dd2b20c0fbb1f2fd7db64d5d3e08e7141a3093007909f98c7984dcc940e9000ac573af6cd81f78d8e20f2fb0b34e6bf01dee9100f458019641dc854920cd8be6f5599e239d68e4b5fef9c257710f4b4009b45086391c6cda3314638dae22a96cfeedf97b52d1fa6c30195f2ce4b1064db23929a38a1103d3d4edd6c9e29203a7b1ba975b681fbcff1e4c6d910dc9e98a02339d1d7d748c877a9726dd653547c8442aa12577a62954c19c24857ea605decf1ede72ce5b159398bd4082cafeaad73cdb5563c45f9476b6069f87dec9e0c18fa2c944806f35c8a07f52e3bf66b545f5457e06d04754a869388596f1653cf951caae15f2d48191ec8db0ec813682cbda38b4aaa3defcef332256fa549ff4fcc9f0b7e08f5c71d4ce6bc366f960e15c0018526b93c58f445e339b14ba5b296c546314de30f2c66508bf4436b6787b095603b918aaff638711ddb8255e1e782d299f48aa9fba0b334cff16e3cc1c43225e17cc51f39215e0d2c2afceaed18358787074475d928a6665130bb8cff4a901a7b8f5ec67298fb9b4d665a0182a11abb55109b838c58ebcb56e29c617fb82b1e1a7c49b934de0d12bd4775ae8abd216848a6cea02ebc44fcd14a7aa9ac09b641fee138d5cad7eeb0a3c23df06846f2bfc8c0a87e4a884915909726c34dddd35111a003f524437bdcbe10b3e60b7d442f39666ad7916c784160be8df"

# ==================== LOAD TEMPLATES ====================
try:
    decrypted_bytes = aes_decrypt(MOBILE_PROTO)
    decrypted_hex = decrypted_bytes.hex()
    proto_json = get_available_room(decrypted_hex)
    proto_fields = json.loads(proto_json)
    proto_template = copy.deepcopy(proto_fields)
    print("✅ Loaded MOBILE_PROTO template")
except Exception as e:
    print(f"❌ Error loading template: {e}")
    proto_template = {}

try:
    decrypted_bytes1 = aes_decrypt(MOBILE_PROTO)
    decrypted_hex1 = decrypted_bytes1.hex()
    proto_json1 = get_available_room(decrypted_hex1)
    proto_fields1 = json.loads(proto_json1)
    proto_template1 = copy.deepcopy(proto_fields1)
    print("✅ Loaded proto_template1")
except Exception as e:
    print(f"❌ Error loading proto_template1: {e}")
    proto_template1 = {}

# ==================== DATABASE SETUP ====================
db = sqlite3.connect(DB_FILE, check_same_thread=False)
cur = db.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT,
    ip TEXT,
    ts INTEGER,
    status TEXT
)
""")
cur.execute("""
CREATE TABLE IF NOT EXISTS stats (
    key TEXT PRIMARY KEY,
    value INTEGER
)
""")
db.commit()

for k in ("total", "allowed", "blocked"):
    cur.execute("INSERT OR IGNORE INTO stats (key, value) VALUES (?, ?)", (k, 0))
db.commit()

def inc_stat(name: str):
    cur.execute("UPDATE stats SET value = value + 1 WHERE key=?", (name,))
    db.commit()

def log_login_db(uid: str, ip: str, status: str):
    ts = int(time.time())
    cur.execute("INSERT INTO login_logs (uid, ip, ts, status) VALUES (?, ?, ?, ?)", (uid, ip, ts, status))
    db.commit()

# ==================== UID CHECK FUNCTIONS ====================
def check_uid_from_firebase(uid: str) -> bool:
    try:
        response = requests.get(FIREBASE_DATABASE_URL, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data:
                for user_data in data.values():
                    uids_list = user_data.get('uids', [])
                    if isinstance(uids_list, list):
                        for uid_data in uids_list:
                            if isinstance(uid_data, dict) and 'uid' in uid_data:
                                if str(uid_data['uid']) == uid:
                                    return True
                            elif isinstance(uid_data, str):
                                if uid_data == uid:
                                    return True
    except Exception as e:
        print(f"[Firebase] Error: {e}")
    return False

def check_uid_from_file(uid: str) -> bool:
    if os.path.exists(UID_FILE):
        try:
            with open(UID_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if line == uid:
                        print(f"[✓] UID {uid} found in uid.txt")
                        return True
        except Exception as e:
            print(f"[File] Error: {e}")
    return False

def checkUIDExists(uid: str) -> bool:
    uid = str(uid).strip()
    print(f"\n[UID CHECK] Checking UID: {uid}")
    if check_uid_from_file(uid):
        return True
    if check_uid_from_firebase(uid):
        print(f"[✓] UID {uid} found in Firebase")
        return True
    print(f"[✗] UID {uid} NOT AUTHORIZED")
    return False

# ==================== MITMPROXY INTERCEPTOR ====================
class MajorLoginInterceptor:
    def request(self, flow: http.HTTPFlow) -> None:
        self._handle_get_login_data(flow)
        if flow.request.method.upper() == "POST" and "/MajorLogin" in flow.request.path:
            try:
                request_bytes = flow.request.content
                request_hex = request_bytes.hex()
                decrypted_bytes = aes_decrypt(request_hex)
                decrypted_hex = decrypted_bytes.hex()
                proto_json = get_available_room(decrypted_hex)
                proto_fields = json.loads(proto_json)

                uid = None
                access_token = None
                open_id = None
                main_active_platform = None
                version_field = None
                event_time = None

                for field_num in ["1", "2", "3"]:
                    if field_num in proto_fields and isinstance(proto_fields[field_num], dict) and "data" in proto_fields[field_num]:
                        potential_uid = str(proto_fields[field_num]["data"])
                        if potential_uid.isdigit() and len(potential_uid) > 5:
                            uid = potential_uid
                            break

                if "3" in proto_fields and isinstance(proto_fields["3"], dict) and "data" in proto_fields["3"]:
                    event_time = str(proto_fields["3"]["data"])
                if "7" in proto_fields and isinstance(proto_fields["7"], dict) and "data" in proto_fields["7"]:
                    version_field = str(proto_fields["7"]["data"])
                if "29" in proto_fields and isinstance(proto_fields["29"], dict) and "data" in proto_fields["29"]:
                    access_token = str(proto_fields["29"]["data"])
                if "22" in proto_fields and isinstance(proto_fields["22"], dict) and "data" in proto_fields["22"]:
                    open_id = str(proto_fields["22"]["data"])
                if "99" in proto_fields and isinstance(proto_fields["99"], dict) and "data" in proto_fields["99"]:
                    main_active_platform = str(proto_fields["99"]["data"])
                elif "100" in proto_fields and isinstance(proto_fields["100"], dict) and "data" in proto_fields["100"]:
                    main_active_platform = str(proto_fields["100"]["data"])

                modified_proto = copy.deepcopy(proto_template)

                if event_time:
                    if "3" in modified_proto and isinstance(modified_proto["3"], dict):
                        modified_proto["3"]["data"] = event_time
                    else:
                        modified_proto["3"] = {"wire_type": "string", "data": event_time}

                if version_field:
                    if "7" in modified_proto and isinstance(modified_proto["7"], dict):
                        modified_proto["7"]["data"] = version_field
                    else:
                        modified_proto["7"] = {"wire_type": "string", "data": version_field}
                else:
                    if "7" in modified_proto and isinstance(modified_proto["7"], dict):
                        modified_proto["7"]["data"] = "1.120.3"
                    else:
                        modified_proto["7"] = {"wire_type": "string", "data": "1.120.3"}

                if "29" in modified_proto and isinstance(modified_proto["29"], dict):
                    modified_proto["29"]["data"] = access_token if access_token else modified_proto["29"].get("data", "")
                if "22" in modified_proto and isinstance(modified_proto["22"], dict):
                    modified_proto["22"]["data"] = open_id if open_id else modified_proto["22"].get("data", "")

                platform_value = main_active_platform or modified_proto.get("99", {}).get("data", "4")

                def set_platform_field(key: str, value: str):
                    wire_type = "string"
                    if key in proto_fields and isinstance(proto_fields[key], dict) and "wire_type" in proto_fields[key]:
                        wire_type = proto_fields[key]["wire_type"]
                    elif key in modified_proto and isinstance(modified_proto[key], dict) and "wire_type" in modified_proto[key]:
                        wire_type = modified_proto[key]["wire_type"]
                    modified_proto[key] = {"wire_type": wire_type, "data": value}

                set_platform_field("99", platform_value)
                set_platform_field("100", platform_value)

                proto_bytes = CrEaTe_ProTo(modified_proto)
                hex_data = encrypt_api(proto_bytes)
                flow.request.content = bytes.fromhex(hex_data)

            except Exception as e:
                print(f"Error processing MajorLogin request: {e}")

    def _handle_get_login_data(self, flow: http.HTTPFlow):
        if flow.request.method.upper() != "POST" or "/GetLoginData" not in flow.request.path:
            return
        try:
            request_bytes = flow.request.content
            request_hex = request_bytes.hex()
            decrypted_bytes = aes_decrypt(request_hex)
            decrypted_hex = decrypted_bytes.hex()
            proto_json = get_available_room(decrypted_hex)
            proto_fields = json.loads(proto_json)

            uid = None
            access_token = None
            open_id = None
            client_version = None
            main_active_platform = None

            for field_num in ["1", "2", "3"]:
                if field_num in proto_fields and isinstance(proto_fields[field_num], dict) and "data" in proto_fields[field_num]:
                    potential_uid = str(proto_fields[field_num]["data"])
                    if potential_uid.isdigit() and len(potential_uid) > 5:
                        uid = potential_uid
                        break

            if "29" in proto_fields and isinstance(proto_fields["29"], dict) and "data" in proto_fields["29"]:
                access_token = str(proto_fields["29"]["data"])
            if "22" in proto_fields and isinstance(proto_fields["22"], dict) and "data" in proto_fields["22"]:
                open_id = str(proto_fields["22"]["data"])
            if "99" in proto_fields and isinstance(proto_fields["99"], dict) and "data" in proto_fields["99"]:
                main_active_platform = str(proto_fields["99"]["data"])
            elif "100" in proto_fields and isinstance(proto_fields["100"], dict) and "data" in proto_fields["100"]:
                main_active_platform = str(proto_fields["100"]["data"])
            if "7" in proto_fields and isinstance(proto_fields["7"], dict) and "data" in proto_fields["7"]:
                client_version = str(proto_fields["7"]["data"])

            modified_proto = copy.deepcopy(proto_template1)

            if client_version:
                if "7" in modified_proto and isinstance(modified_proto["7"], dict):
                    modified_proto["7"]["data"] = client_version
                else:
                    modified_proto["7"] = {"wire_type": "string", "data": client_version}
            else:
                if "7" in modified_proto and isinstance(modified_proto["7"], dict):
                    modified_proto["7"]["data"] = "1.120.3"
                else:
                    modified_proto["7"] = {"wire_type": "string", "data": "1.120.3"}

            if "29" in modified_proto and isinstance(modified_proto["29"], dict):
                modified_proto["29"]["data"] = access_token if access_token else modified_proto["29"].get("data", "")
            if "22" in modified_proto and isinstance(modified_proto["22"], dict):
                modified_proto["22"]["data"] = open_id if open_id else modified_proto["22"].get("data", "")

            def set_platform_field(key: str, value: str):
                wire_type = "string"
                if key in proto_fields and isinstance(proto_fields[key], dict) and "wire_type" in proto_fields[key]:
                    wire_type = proto_fields[key]["wire_type"]
                elif key in modified_proto and isinstance(modified_proto[key], dict) and "wire_type" in modified_proto[key]:
                    wire_type = modified_proto[key]["wire_type"]
                modified_proto[key] = {"wire_type": wire_type, "data": value}

            platform_value = main_active_platform or modified_proto.get("99", {}).get("data", "0")
            set_platform_field("99", platform_value)
            set_platform_field("100", platform_value)

            proto_bytes = CrEaTe_ProTo(modified_proto)
            hex_data = encrypt_api(proto_bytes)
            flow.request.content = bytes.fromhex(hex_data)

        except Exception as e:
            print(f"Error processing GetLoginData request: {e}")

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.request.method.upper() != "POST":
            return
        if "majorlogin" not in flow.request.path.lower():
            return

        inc_stat("total")

        try:
            respBody = flow.response.content.hex()
            proto_json = get_available_room(respBody)
            proto_fields = json.loads(proto_json)

            uid = None
            for field_num in ["1", "2", "3"]:
                if field_num in proto_fields and isinstance(proto_fields[field_num], dict) and "data" in proto_fields[field_num]:
                    potential_uid = str(proto_fields[field_num]["data"])
                    if potential_uid.isdigit() and len(potential_uid) > 5:
                        uid = potential_uid
                        break

            if not uid:
                return

            client_ip = None
            try:
                if flow.client_conn and flow.client_conn.peername:
                    client_ip = flow.client_conn.peername[0]
            except:
                pass

            if not checkUIDExists(uid):
                inc_stat("blocked")
                log_login_db(uid, client_ip, "BLOCKED")

                # ========== ERROR MESSAGE (like bypass.py) ==========
                error_message = WHITELIST_MSG.format(uid=uid).encode()
                flow.response.content = error_message
                flow.response.status_code = 400
                flow.response.headers["Content-Type"] = "text/plain"
                return

            inc_stat("allowed")
            log_login_db(uid, client_ip, "ALLOWED")

        except Exception as e:
            print(f"Error processing response: {e}")

addons = [MajorLoginInterceptor()]

# ==================== STARTUP ====================
if __name__ == "__main__":
    print(f"MITM proxy on 0.0.0.0:{LISTEN_PORT}")
    print(f"UID file: {UID_FILE}")
    print(f"Firebase: {FIREBASE_DATABASE_URL}")
    
    script_path = os.path.abspath(__file__).replace('\\', '\\\\')
    proc = subprocess.Popen(
        [
            sys.executable, "-c",
            f"import sys; from mitmproxy.tools.main import mitmdump; sys.argv = ['mitmdump', '-s', '{script_path}', '-p', '{LISTEN_PORT}', '--listen-host', '0.0.0.0', '--set', 'block_global=false']; mitmdump()",
        ]
    )
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        print("Shutdown...")