# server_authority.py
import socket
import threading
import json
import logging
import RSA  
import time

# Setup Logging untuk mencatat aktivitas server
logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Penyimpanan klien dan antrian pesan
clients = {}      # key: username -> socket
queued = {}       # key: username -> [messages]

# Registry user yang menyimpan public key + ip + port
# Format: users[username] = {"e": e, "n": n, "ip": ip, "port": port}
users = {}

# Kunci untuk autentikasi klien (misalnya, token atau password)
valid_credentials = {
    "A": "passwordA",
    "B": "passwordB"
}

# Authority RSA keypair (digenerate saat server start)
rsa_server = RSA.rsa()
my_pu, my_pr = RSA.generateKeyPair()
logging.info(f"Authority public key (e,n): ({my_pu.e}, {my_pu.n})")

def safe_send(conn, obj):
    """Mengirim JSON dengan aman (untuk pesan chat)."""
    try:
        data = json.dumps(obj).encode()
        conn.sendall(data)
        return True
    except Exception as e:
        logging.error(f"Kesalahan saat mengirim data: {e}")
        return False

def deliver_or_queue(target, msg):
    """Kirim pesan ke target, atau queue kalau target belum connect."""
    if clients.get(target):
        ok = safe_send(clients[target], msg)
        if not ok:
            queued[target].append(msg)
    else:
        if target not in queued:
            queued[target] = []
        queued[target].append(msg)

def flush_queue(username):
    """Mengirim semua pesan yang sebelumnya ditahan untuk username."""
    if username not in clients or not clients[username]:
        return
    for msg in queued.get(username, []):
        safe_send(clients[username], msg)
    queued[username] = []

def extract_json_packets(buffer):
    """Mengambil JSON dari stream TCP yang mungkin pecah atau tergabung."""
    packets = []
    brace = 0
    start = None

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

    # Sisanya buffer yang belum jadi JSON lengkap
    if brace == 0:
        remainder = b""
    else:
        remainder = buffer[start:] if start is not None else buffer

    return packets, remainder

def authenticate_client(conn, role):
    """
    Autentikasi klien berdasarkan username dan password.
    Returns username (str) if success, else None.
    """
    try:
        auth_data = conn.recv(4096)
        auth_json = json.loads(auth_data.decode())
        username = auth_json.get("username")
        password = auth_json.get("password")

        # Cek kredensial
        if valid_credentials.get(username) == password:
            safe_send(conn, {"status": "authenticated"})
            logging.info(f"[SERVER] {role} authenticated as {username}")
            return username
        else:
            safe_send(conn, {"status": "unauthorized"})
            logging.warning(f"[SERVER] {role} failed auth as {username}")
            return None
    except Exception as e:
        logging.error(f"Kesalahan autentikasi: {e}")
        return None

def handle_client(conn, role):
    """Menangani komunikasi dengan klien A/B. Ini juga menerima pubkey register."""
    try:
        # authenticate: returns username or None
        username = authenticate_client(conn, role)
        if username is None:
            conn.close()
            return

        # register connection
        clients[username] = conn
        if username not in queued:
            queued[username] = []

        # flush any queued messages
        flush_queue(username)
        logging.info(f"[SERVER] {username} connected as role {role}")

        buffer = b""
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buffer += data
            packets, buffer = extract_json_packets(buffer)

            for packet in packets:
                try:
                    msg = json.loads(packet.decode())
                except Exception as e:
                    logging.error(f"Kesalahan parsing JSON from {username}: {e}")
                    continue

                # handle registration of public key from client
                # expected format:
                # {"type":"pubkey", "e": "<decimal>", "n": "<decimal>", "ip":"1.2.3.4", "port": 5000}
                if msg.get("type") == "pubkey":
                    try:
                        e = int(msg.get("e"))
                        n = int(msg.get("n"))
                        ip = msg.get("ip")
                        port = int(msg.get("port"))
                        users[username] = {"e": e, "n": n, "ip": ip, "port": port}
                        logging.info(f"[SERVER] Registered pubkey for {username}")
                        safe_send(conn, {"status": "pubkey_registered"})
                    except Exception as ex:
                        logging.error(f"[SERVER] Failed to register pubkey for {username}: {ex}")
                        safe_send(conn, {"status": "pubkey_failed"})
                    continue

                # chat type forwarding
                if msg.get("type") == "chat":
                    # infer target: if sender is A -> B, else -> A
                    target = "B" if username == "A" else "A"
                    # but we store clients by username; prefer to map roles to usernames if needed.
                    # Here we attempt to deliver to username 'target' only if exists, else we attempt any user with role
                    deliver_or_queue(target, msg)
                # allow direct deliver by specifying "to" field
                elif msg.get("type") == "direct":
                    to_user = msg.get("to")
                    if to_user:
                        deliver_or_queue(to_user, msg)
                elif msg.get("type") == "des_key":
                    # A sends DES key message: forward to target or queue
                    target = msg.get("to")
                    if not target:
                        target = "B" if username == "A" else "A"
                    deliver_or_queue(target, msg)
                # other message types can be forwarded similarly
        # end while
    except Exception as e:
        logging.error(f"Kesalahan saat menerima data dari {role}: {e}")
    finally:
        print(f"[SERVER] {role} disconnected")
        # cleanup: remove client socket if present
        # find username for this conn
        to_remove = None
        for u, c in list(clients.items()):
            if c == conn:
                to_remove = u
                break
        if to_remove:
            clients[to_remove] = None
        conn.close()

def handleAuth(conn):
    try:
        # 1. Terima request (maks 1024 byte)
        # recv() di sini nge-blok sampe klien ngirim 'GETKEY <nama>'
        request_bytes = conn.recv(1024)
        if not request_bytes:
            logging.warning("[AUTH_SERVER] Menerima request GETKEY kosong.")
            conn.close()
            return

        text = request_bytes.decode('utf-8').strip()
        parts = text.split()

        # 2. Validasi format request
        if len(parts) != 2 or parts[0].upper() != "GETKEY":
            conn.sendall(b"ERROR: Invalid request format. Use: GETKEY <username>")
            logging.warning(f"[AUTH_SERVER] Request format salah: {text}")
            conn.close()
            return

        username = parts[1]
        logging.info(f"[AUTH_SERVER] Menerima request GETKEY untuk: {username}")

        # 3. Cari user di database (yang diisi sama server Chat)
        info = users.get(username)
        if not info:
            conn.sendall(f"ERROR: User '{username}' not found in registry.".encode('utf-8'))
            logging.warning(f"[AUTH_SERVER] User {username} tidak ditemukan.")
            conn.close()
            return

        # 4. Bikin "KTP" (Payload)
        # Format: "e|n|ip|port"
        payload = f"{info['e']}|{info['n']}|{info['ip']}|{info['port']}"
        payload_bytes = payload.encode('utf-8')

        # 5. Tanda Tangan (Sign) payload pake Kunci Privat Otoritas
        # (Memanggil rsa_server.sign(pesan, kunci_privat_otoritas))
        sig_int = rsa_server.sign(payload, my_pr)
        sig_bytes = str(sig_int).encode('utf-8')

        # 6. Kirim Sertifikat (Payload + Tanda Tangan)
        # Format: payload||tanda_tangan
        cert = payload_bytes + b"||" + sig_bytes
        conn.sendall(cert)
        
        logging.info(f"[AUTH_SERVER] Berhasil mengirim sertifikat {username}.")

    except Exception as e:
        logging.error(f"[AUTH_SERVER] Error di handleAuth_v2: {e}")
        try:
            conn.sendall(b"ERROR: Internal server error.")
        except:
            pass # Kalo send error juga, yaudah
    finally:
        # 7. Tutup koneksi (WAJIB)
        conn.close()

def main():
    print("===== SERVER KI (PKD + Chat Relay) =====")
    
    # --- Bikin Thread buat Authority Server (Port 3000) ---
    def start_auth_server():
        auth_port = 3000
        auth_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        auth_server.bind(("0.0.0.0", auth_port))
        auth_server.listen(5)
        logging.info(f"[AUTH_SERVER] Berjalan di port {auth_port} (GETKEY)...")
        
        while True:
            conn, addr = auth_server.accept()
            logging.info(f"[AUTH_SERVER] Ada request GETKEY dari {addr}")
            # Langsung kasih ke handler-nya
            # handleAuth SEKARANG HARUS BACA DARI 'conn' (bukan 'initial_bytes')
            threading.Thread(target=handleAuth, args=(conn,), daemon=True).start()

    # --- Bikin Thread buat Chat Relay Server (Port 3001) ---
    def start_chat_server():
        chat_port = 3001
        chat_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        chat_server.bind(("0.0.0.0", chat_port))
        chat_server.listen(5)
        logging.info(f"[CHAT_SERVER] Berjalan di port {chat_port} (A/B Login)...")
        print("Server menerima koneksi")
        
        while True:
            conn, addr = chat_server.accept()
            logging.info(f"[CHAT_SERVER] Ada koneksi klien dari {addr}")
            # Asumsi klien ngirim "A" atau "B" dulu
            try:
                role = conn.recv(1024).decode().strip()
                if role in ("A", "B"):
                    threading.Thread(target=handle_client, args=(conn, role), daemon=True).start()
                else:
                    conn.close()
            except Exception:
                conn.close()

    # --- Jalankan kedua server ---
    threading.Thread(target=start_auth_server, daemon=True).start()
    threading.Thread(target=start_chat_server, daemon=True).start()
    
    # Bikin main thread tetep jalan
    try:
        while True:
            time.sleep(60) # Tidur aja, biarin thread lain kerja
    except KeyboardInterrupt:
        print("Server dihentikan.")

if __name__ == "__main__":
    main()
