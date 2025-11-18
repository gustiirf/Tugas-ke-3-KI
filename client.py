# client_dynamic_final.py
import socket
import threading
import json
import RSA
import DES
import sys

rsa_crypto = RSA.rsa()
des_crypto = DES.des()

AUTH_HOST = "127.0.0.1"
AUTH_PORT = 3000
CHAT_HOST = "127.0.0.1"
CHAT_PORT = 3001

authority_pu = None
my_pu, my_pr = RSA.generateKeyPair()
user_password = None
user_cache = {}

def parseData(payload):
    e, n, ip, port = payload.split("|")
    return (int(e), int(n)), ip, int(port)

def fetchAuthPU():
    global authority_pu

    try:
        sock = socket.create_connection((AUTH_HOST, AUTH_PORT))
        sock.sendall(b"GETPUBKEY")
        data = sock.recv(4096).decode().strip()
        sock.close()

        if "|" not in data:
            raise RuntimeError("Invalid authority pubkey format from server")

        e_str, n_str = data.split("|", 1)
        e = int(e_str)
        n = int(n_str)
        print(f"e adalah {e} n adalah {n}")

        authority_pu = RSA.PU(e, n)
        print(f"[Client] Authority Public Key Loaded dynamically: e={e}, n={n}")

    except Exception as e:
        print("[ERROR] Failed to fetch authority public key:", e)
        sys.exit(1)

def getLocalIP():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"
    
def register_user(username, port):
    global user_password

    s = socket.create_connection((CHAT_HOST, CHAT_PORT))
    my_ip = getLocalIP()
    payload = {
        "type": "register",
        "username": username,
        "e": my_pu.e,
        "n": my_pu.n,
        "ip": my_ip,
        "port": port
    }

    s.sendall(json.dumps(payload).encode())
    reply = json.loads(s.recv(4096).decode())
    s.close()

    if reply["status"] == "registered":
        user_password = reply["password"]
        print(f"[CLIENT] Registered! Assigned password = {user_password}")
    else:
        print("[CLIENT] Registration failed")
        sys.exit(1)

def getUserAuth(username):
    if username in user_cache:
        return user_cache[username]

    s = socket.create_connection((AUTH_HOST, AUTH_PORT))
    s.sendall(f"GETKEY {username}".encode())
    cert = s.recv(8192)
    s.close()

    if b"||" not in cert:
        raise RuntimeError("Invalid CERT format")

    payload, signature = cert.split(b"||", 1)
    payload_str = payload.decode()
    sig_int = int(signature.decode())

    if not rsa_crypto.verify(payload_str, sig_int, authority_pu):
        raise RuntimeError("Authority signature invalid!")

    pu_target, ip_target, port_target = parseData(payload_str)
    user_cache[username] = (pu_target, ip_target, port_target)
    return user_cache[username]


def listenerThread(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)

    print(f"[CLIENT] Listening on port {port} ...")

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handleIncoming, args=(conn,), daemon=True).start()


def handleIncoming(conn):
    try:
        key_len = int.from_bytes(conn.recv(4), "big")
        key_bytes = conn.recv(key_len)
        key_int = int.from_bytes(key_bytes, "big")
        session_hex = rsa_crypto.decrypt(key_int, my_pr)

        session_bin = DES.hexToBin(session_hex)
        round_keys = des_crypto.keySchedule(session_bin)

        block_count = int.from_bytes(conn.recv(4), "big")
        blocks = []

        for _ in range(block_count):
            blk = conn.recv(16).decode() 
            blocks.append(blk)

        bin_full = ""
        for blk in blocks:
            bin_blk = DES.hexToBin(blk)
            dec_blk = des_crypto.decrypt(bin_blk, round_keys)
            bin_full += dec_blk

        clean = DES.removePadding(bin_full)
        msg = DES.binToASCII(clean)

        print(f"\n📩 New Message: {msg}\n> ", end="")

    except Exception as e:
        print("[ERROR receiving]:", e)

    finally:
        conn.close()

def sendMsg(pu_target, ip_target, port_target, msg):
    session_hex = DES.generateRandomKey()
    session_bin = DES.hexToBin(session_hex)
    round_keys = des_crypto.keySchedule(session_bin)

    pu_e, pu_n = pu_target
    pu_obj = RSA.PU(pu_e, pu_n)
    enc_key_int = rsa_crypto.encrypt(session_hex, pu_obj)
    key_bytes = RSA.intToByte(enc_key_int)

    bin_msg = DES.ASCIItoBin(msg)
    padded = DES.addPadding(bin_msg)
    blocks = DES.splitBlocks(padded)

    sock = socket.create_connection((ip_target, port_target))

    sock.sendall(len(key_bytes).to_bytes(4, "big"))
    sock.sendall(key_bytes)

    sock.sendall(len(blocks).to_bytes(4, "big"))

    for blk in blocks:
        enc_blk = des_crypto.encrypt(blk, round_keys)
        hex_blk = DES.binToHex(enc_blk)
        sock.sendall(hex_blk.encode())

    sock.close()

def chat(username):
    print("Type: send | quit")

    while True:
        cmd = input("> ").lower().strip()

        if cmd == "quit":
            print("Bye!")
            return

        if cmd == "send":
            target = input("Send to who: ")
            msg = input("Message: ")

            pu_target, ip_target, port_target = getUserAuth(target)
            sendMsg(pu_target, ip_target, port_target, msg)
            print("[CLIENT] Sent!")

def main():
    if len(sys.argv) != 3:
        print("Usage: python client_dynamic_final.py <username> <port>")
        return

    username = sys.argv[1]
    port = int(sys.argv[2])
    
    global AUTH_HOST, CHAT_HOST
    print("--- Setup Server Connection ---")
    server_ip = input("Masukkan IP: ").strip()

    AUTH_HOST = server_ip
    CHAT_HOST = server_ip
    
    fetchAuthPU()

    threading.Thread(target=listenerThread, args=(port,), daemon=True).start()
    register_user(username, port)

    chat(username)


if __name__ == "__main__":
    main()
