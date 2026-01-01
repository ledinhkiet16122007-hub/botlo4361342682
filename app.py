import threading
import json
import time
import logging
import socket
import sys
import os
import base64
import binascii
import requests
import jwt
import psutil
import re
from datetime import datetime
from flask import Flask, jsonify, request

# Import Protobuf libs
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.json_format import MessageToJson
import jwt_generator_pb2
import MajorLoginRes_pb2

# Crypto libs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import local modules
try:
    from protobuf_decoder.protobuf_decoder import Parser
    from important_zitado import *
    from byte import *
except ImportError as e:
    print(f"CRITICAL ERROR: Thiếu file hoặc module: {e}")
    print("Hãy đảm bảo folder chứa: app.py, byte.py, important_zitado.py và thư mục protobuf_decoder")
    sys.exit(1)

app = Flask(__name__)
bot_instance = None  
log_buffer = []      

# Cấu hình thời gian
START_SPAM_DURATION = 18       
WAIT_AFTER_MATCH_SECONDS = 20  
START_SPAM_DELAY = 0.2         

def log_message(msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] {msg}"
    print(formatted_msg)  
    log_buffer.append(formatted_msg) 
    if len(log_buffer) > 50: 
        log_buffer.pop(0)

def restart_program():
    log_message("Đang khởi động lại bot...")
    python = sys.executable
    os.execl(python, python, *sys.argv)

def encrypt_packet(plain_text, key, iv):
    if isinstance(key, str): key = bytes.fromhex(key)
    if isinstance(iv, str): iv = bytes.fromhex(iv)
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        # Giả sử byte.py có hàm parse_results, nếu không dùng logic đơn giản
        from byte import parse_results as pr
        parsed_results_dict = pr(parsed_results)
        return json.dumps(parsed_results_dict)
    except Exception as e:
        return None

def dec_to_hex(ask: int) -> str:
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
    return final_result

# =============================================================================
# CLASS XỬ LÝ UDP (VÀO TRẬN)
# =============================================================================
class GameClientUDP(threading.Thread):
    def __init__(self, ip, port, token, uid):
        super().__init__()
        self.ip = ip
        self.port = int(port)
        self.token = token 
        self.uid = uid
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP Socket
        self.running = True
        self.connected = False

    def create_handshake_packet(self):
        """Tạo gói tin bắt tay UDP để server cho phép vào trận"""
        try:
            # --- [QUAN TRỌNG] HEADER UDP ---
            # Bạn cần check gói tin đầu tiên trong PCapDroid tab Payload
            # Nó thường là 81, 00, 01 hoặc magic bytes khác tùy version.
            HEADER = "81" 
            
            # Xử lý Token (Nếu token là chuỗi hex thì decode, nếu raw string thì encode)
            if isinstance(self.token, str):
                # Thử đoán xem token là hex hay string thường
                if len(self.token) > 20 and all(c in '0123456789abcdefABCDEF' for c in self.token):
                     token_bytes = bytes.fromhex(self.token)
                else:
                     token_bytes = self.token.encode('utf-8')
            else:
                token_bytes = self.token
            
            token_len_hex = dec_to_hex(len(token_bytes))
            token_hex = token_bytes.hex()
            
            # UID sang Hex
            uid_hex = hex(int(self.uid))[2:]
            if len(uid_hex) % 2 != 0: uid_hex = "0" + uid_hex
            
            # Ghép gói tin: Header + Len + Token + UID (Cấu trúc phổ biến)
            packet_hex = f"{HEADER}{token_len_hex}{token_hex}{uid_hex}"
            return bytes.fromhex(packet_hex)
        except Exception as e:
            log_message(f"[UDP] Lỗi tạo Handshake: {e}")
            return None

    def run(self):
        log_message(f"[UDP] Đang kết nối vào trận: {self.ip}:{self.port}...")
        
        # 1. Gửi Handshake
        pkt = self.create_handshake_packet()
        if pkt:
            self.sock.sendto(pkt, (self.ip, self.port))
            log_message("[UDP] Đã gửi gói tin Handshake.")
        else:
            log_message("[UDP] Không thể tạo gói tin Handshake.")
            return

        self.sock.settimeout(3.0)
        last_ping = time.time()
        
        # 2. Vòng lặp giữ kết nối trong trận
        while self.running:
            try:
                # Gửi Ping UDP mỗi giây (Giữ kết nối)
                if time.time() - last_ping > 1.0:
                    # Gói ping rỗng 00 thường được chấp nhận
                    self.sock.sendto(bytes.fromhex("00"), (self.ip, self.port))
                    last_ping = time.time()

                # Nhận dữ liệu từ Game Server
                try:
                    data, _ = self.sock.recvfrom(2048)
                    if not self.connected:
                        log_message(f"[UDP] KẾT NỐI THÀNH CÔNG! Đã vào trận. (Recv: {len(data)} bytes)")
                        self.connected = True
                except socket.timeout:
                    continue
                    
            except Exception as e:
                log_message(f"[UDP] Lỗi vòng lặp: {e}")
                break
        
        self.sock.close()
        log_message("[UDP] Đã ngắt kết nối.")

    def stop(self):
        self.running = False

# =============================================================================
# CLASS XỬ LÝ TCP (LOBBY/SẢNH)
# =============================================================================
class FF_CLIENT(threading.Thread):
    def __init__(self, uid, password):
        super().__init__()
        self.id = uid
        self.password = password
        self.key = None
        self.iv = None
        
        self.auto_start_running = False
        self.auto_start_teamcode = None
        self.stop_auto = False
        
        self.socket_client = None 
        self.clients = None   
        self.udp_client = None    
        
        self.get_tok()

    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(MajorLogRes.kts)
        combined_timestamp = timestamp_obj.seconds * 1_000_000_000 + timestamp_obj.nanos
        return combined_timestamp, MajorLogRes.ak, MajorLogRes.aiv, MajorLogRes.token

    def GET_PAYLOAD_BY_DATA(self, JWT_TOKEN, NEW_ACCESS_TOKEN, date):
        try:
            token_payload_base64 = JWT_TOKEN.split(".")[1]
            token_payload_base64 += "=" * ((4 - len(token_payload_base64) % 4) % 4)
            decoded_payload = json.loads(base64.urlsafe_b64decode(token_payload_base64).decode("utf-8"))
            
            NEW_EXTERNAL_ID = decoded_payload["external_id"]
            SIGNATURE_MD5 = decoded_payload["signature_md5"]
            now = str(datetime.now())[:19]

            # Payload gốc (Hardcoded hex string từ dump)
            payload_hex = "1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131382e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033"
            payload = bytes.fromhex(payload_hex)
            
            payload = payload.replace(b"2025-07-30 11:02:51", now.encode())
            payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", NEW_ACCESS_TOKEN.encode("UTF-8"))
            payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8"))
            payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))

            PAYLOAD = encrypt_api(payload.hex())
            whisper_ip, whisper_port, online_ip, online_port = self.GET_LOGIN_DATA(JWT_TOKEN, bytes.fromhex(PAYLOAD))
            return whisper_ip, whisper_port, online_ip, online_port
        except Exception as e:
            log_message(f"Payload Gen Error: {e}")
            return None, None, None, None

    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://clientbp.ggpolarbear.com/GetLoginData"
        headers = {
            "Authorization": f"Bearer {JWT_TOKEN}",
            "X-Unity-Version": "2018.4.11f1", "X-GA": "v1 1", "ReleaseVersion": "Ob51",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
            "Host": "clientbp.common.ggbluefox.com", "Connection": "close"
        }
        try:
            response = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
            x = response.content.hex()
            json_result = get_available_room(x)
            parsed_data = json.loads(json_result)
            
            whisper_address = parsed_data["32"]["data"]
            online_address = parsed_data["14"]["data"]
            
            w_ip = whisper_address[:len(whisper_address)-6]
            w_port = int(whisper_address[len(whisper_address)-5:])
            o_ip = online_address[:len(online_address)-6]
            o_port = int(online_address[len(online_address)-5:])
            
            return w_ip, w_port, o_ip, o_port
        except Exception as e:
            log_message(f"Failed to get login data: {e}")
            return None, None, None, None

    def guest_token(self, uid, password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com", "User-Agent": "GarenaMSDK/4.0.19P4", "Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "uid": f"{uid}", "password": f"{password}", "response_type": "token",
            "client_type": "2", "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        try:
            resp = requests.post(url, headers=headers, data=data).json()
            return self.TOKEN_MAKER("ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", resp["access_token"], "996a629dbcdb3964be6b6978f5d814db", resp["open_id"], uid)
        except Exception as e:
            log_message(f"Guest Token Error: {e}")
            return False

    def TOKEN_MAKER(self, OLD_AT, NEW_AT, OLD_OID, NEW_OID, id):
        headers = {
            "X-Unity-Version": "2018.4.11f1", "ReleaseVersion": "Ob51",
            "Content-Type": "application/x-www-form-urlencoded", "X-GA": "v1 1",
            "User-Agent": "Dalvik/2.1.0", "Host": "loginbp.ggblueshark.com"
        }
        data_hex = "1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131382e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033"
        data = bytes.fromhex(data_hex)
        data = data.replace(OLD_OID.encode(), NEW_OID.encode())
        data = data.replace(OLD_AT.encode(), NEW_AT.encode())
        
        Final_Payload = bytes.fromhex(encrypt_api(data.hex()))
        RESPONSE = requests.post("https://loginbp.ggblueshark.com/MajorLogin", headers=headers, data=Final_Payload, verify=False)
        
        if RESPONSE.status_code == 200 and len(RESPONSE.text) > 10:
            combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
            w_ip, w_port, o_ip, o_port = self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN, NEW_AT, 1)
            self.key, self.iv = key, iv
            return (BASE64_TOKEN, key, iv, combined_timestamp, w_ip, w_port, o_ip, o_port)
        return False

    def nmnmmmmn(self, data_hex):
        key, iv = self.key, self.iv
        data = bytes.fromhex(data_hex)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(data, AES.block_size)).hex()

    def start_autooo(self):
        try:
            # Gói tin Start (Cần update timestamp để tránh bị coi là packet cũ)
            fields = {1: 9, 2: {1: 12480598706}} 
            packet = create_protobuf_packet(fields).hex()
            
            encrypted_packet = self.nmnmmmmn(packet)
            header_length = len(encrypted_packet) // 2
            header_length_final = dec_to_hex(header_length)
            
            # Xây dựng header length
            zeros = "0" * (10 - len(header_length_final)) # Logic đơn giản hóa
            if len(header_length_final) == 2: final_packet = "0515000000" + header_length_final + encrypted_packet
            elif len(header_length_final) == 3: final_packet = "051500000" + header_length_final + encrypted_packet
            else: final_packet = "05150000" + header_length_final + encrypted_packet
                
            return bytes.fromhex(final_packet)
        except Exception as e:
            log_message(f"Error making start packet: {e}")
            return None

    def leave_s(self):
        try:
            fields = {1: 7, 2: {1: 12480598706}}
            packet = create_protobuf_packet(fields).hex()
            encrypted_packet = self.nmnmmmmn(packet)
            header_length = dec_to_hex(len(encrypted_packet) // 2)
            
            if len(header_length) == 2: final_packet = "0515000000" + header_length + encrypted_packet
            else: final_packet = "051500000" + header_length + encrypted_packet
                
            return bytes.fromhex(final_packet)
        except Exception as e:
            return None

    def auto_start_loop(self, team_code):
        log_message(f"--- LOOP STARTED for Team: {team_code} ---")
        
        while not self.stop_auto:
            try:
                if self.socket_client is None:
                    time.sleep(5)
                    continue

                log_message(f"Joining {team_code}...")
                try:
                    # Gọi hàm join từ byte.py (đảm bảo hàm này đã được import)
                    join_teamcode(self.socket_client, team_code, self.key, self.iv)
                except Exception as e:
                    log_message(f"Join failed: {e}")
                
                time.sleep(2)

                start_packet = self.start_autooo()
                if start_packet:
                    end_time = time.time() + START_SPAM_DURATION
                    # Spam Start
                    while time.time() < end_time and not self.stop_auto:
                        try:
                            self.socket_client.send(start_packet)
                            time.sleep(START_SPAM_DELAY)
                        except Exception:
                            break 
                
                if self.stop_auto: break

                log_message(f"Đang chờ tìm trận ({WAIT_AFTER_MATCH_SECONDS}s)...")
                # Trong thời gian này, sock_online sẽ lắng nghe gói tin "Match Found"
                time.sleep(WAIT_AFTER_MATCH_SECONDS)
                
                if self.stop_auto: break

                leave_pkt = self.leave_s()
                if leave_pkt:
                    try:
                        self.socket_client.send(leave_pkt)
                        log_message("Hủy tìm trận/Rời nhóm để thử lại...")
                    except Exception:
                        pass
                
                time.sleep(2)

            except Exception as e:
                log_message(f"Loop error: {e}")
                time.sleep(5)

    def api_start_team(self, team_code):
        if self.auto_start_running:
            return f"Bot đang chạy team {self.auto_start_teamcode}. Dùng /stop trước."
        
        self.auto_start_running = True
        self.auto_start_teamcode = team_code
        self.stop_auto = False
        
        t = threading.Thread(target=self.auto_start_loop, args=(team_code,), daemon=True)
        t.start()
        
        msg = f"Đã bật Auto Start cho team {team_code}"
        log_message(msg)
        return msg

    def api_stop_bot(self):
        if not self.auto_start_running:
            return "Bot chưa chạy."
        
        self.stop_auto = True
        self.auto_start_running = False
        tc = self.auto_start_teamcode
        self.auto_start_teamcode = None
        
        if self.udp_client:
           ("Login thất bại. Kiểm tra api_start(team_code):
    if not bot_instance:
        return jsonify({"status": "error", "message": "Bot not initialized."})
    
    if not team_code.isdigit():
        return jsonify({"status": "error", "message": "Team code must be numeric."})

    msg = bot_instance.api_start_team(team_code)
    return jsonify({
        "status": "success",
        "command": f"/start/{team_code}",
        "message": msg,
        "logs": log_buffer[-5:]
    })

@app.route('/stop')
def api_stop():
    if not bot_instance:
        return jsonify({"status": "error", "message": "Bot not initialized."})
    
    msg = bot_instance.api_stop_bot()
    return jsonify({
        "status": "success",
        "command": "/stop",
        "message": msg,
        "logs": log_buffer[-5:]
    })

def start_bot_background():
    global bot_instance
    try:
        if not os.path.exists("bot.txt"):
            log_message("Error: bot.txt not found!")
            return
            
        with open("bot.txt", "r") as file:
            data = json.load(file)
        
        if not data:
            log_message("Error: bot.txt is empty!")
            return

        uid, pwd = list(data.items())[0]
        log_message(f"Starting bot for UID: {uid}")
        bot_instance = FF_CLIENT(uid, pwd)
    except Exception as e:
        log_message(f"Bot init failed: {e}")

if __name__ == "__main__":
    t = threading.Thread(target=start_bot_background)
    t.start()
    
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
