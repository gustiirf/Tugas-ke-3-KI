# server_authority_dynamic.py
import socket
import threading
import json
import logging
import RSA
import time
import secrets

logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(message)s')

clients = {}
queued = {}
users = {}
valid_credentials = {}

rsa_server = RSA.rsa()
my_pu, my_pr = RSA.generateKeyPair()
logging.info(f"Authority public key (e,n): ({my_pu.e}, {my_pu.n})")


def safe_send(conn, obj):
    try:
        conn.sendall(json.dumps(obj).encode())
        return True
    except Exception as e:
        logging.error(f"Send error: {e}")
        return False


def extract_json_packets(buffer):
    packets = []
    brace, start = 0, None
    for i, ch in enumerate(buffer):
        if ch == ord('{'):
            if brace == 0:
                start = i
            brace += 1
        elif ch == ord('}'):
            brace -= 1
            if brace == 0 and start is not None:
                packets.append(buffer[start:i+1])
                start = None
    remainder = buffer[start:] if brace != 0 and start is not None else b""
    return packets, remainder


def handle_chat_client(conn):
    buffer = b""

    while True:
        data = conn.recv(4096)
        if not data:
            break

        buffer += data
        packets, buffer = extract_json_packets(buffer)

        for packet in packets:
            msg = json.loads(packet.decode())

            if msg.get("type") == "register":
                username = msg["username"]
                e = msg["e"]
                n = msg["n"]
                ip = msg["ip"]
                port = msg["port"]

                users[username] = {"e": e, "n": n, "ip": ip, "port": port}

                password = secrets.token_hex(16)
                valid_credentials[username] = password

                safe_send(conn, {"status": "registered", "password": password})
                logging.info(f"[REGISTER] {username} registered pubkey & got password {password}")

                clients[username] = conn
                if username not in queued:
                    queued[username] = []
                continue

            if msg.get("type") == "login":
                username = msg["username"]
                password = msg["password"]

                if valid_credentials.get(username) == password:
                    safe_send(conn, {"status": "authenticated"})
                    clients[username] = conn
                    logging.info(f"[LOGIN] User {username} authenticated")
                else:
                    safe_send(conn, {"status": "unauthorized"})
                    logging.warning(f"[LOGIN FAIL] {username} wrong password")
                continue

            if msg.get("type") == "chat":
                to = msg["to"]
                if to in clients and clients[to]:
                    safe_send(clients[to], msg)
                else:
                    queued.setdefault(to, []).append(msg)
                continue

    conn.close()

def auth_dispatcher(conn):
    try:
        req = conn.recv(1024).decode().strip()

        if req == "GETPUBKEY":
            conn.sendall(f"{my_pu.e}|{my_pu.n}".encode())
            conn.close()
            return
        elif req.startswith("GETKEY"):
            handleAuth(conn, req)

    except Exception as e:
        logging.error(f"[AUTH_SERVER] Error dispatcher: {e}")
        try:
            conn.sendall(b"ERROR")
        except:
            pass
        conn.close()


def handleAuth(conn, req):
    try:
        parts = req.split()

        if len(parts) != 2 or parts[0].upper() != "GETKEY":
            conn.sendall(b"ERROR: invalid request")
            conn.close()
            return

        username = parts[1]
        info = users.get(username)
        if not info:
            conn.sendall(b"ERROR: user not found")
            conn.close()
            return

        payload = f"{info['e']}|{info['n']}|{info['ip']}|{info['port']}"
        sig = rsa_server.sign(payload, my_pr)

        cert = payload.encode() + b"||" + str(sig).encode()
        conn.sendall(cert)

    finally:
        conn.close()


def main():
    print("AUTH+CHAT Server running...")

    def auth_server_thread():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", 3000))
        s.listen(5)
        while True:
            conn, _ = s.accept()
            threading.Thread(target=auth_dispatcher, args=(conn,), daemon=True).start()

    def chat_server_thread():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", 3001))
        s.listen(5)
        while True:
            conn, _ = s.accept()
            threading.Thread(target=handle_chat_client, args=(conn,), daemon=True).start()

    threading.Thread(target=auth_server_thread, daemon=True).start()
    threading.Thread(target=chat_server_thread, daemon=True).start()

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
