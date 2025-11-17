import socket
import threading
import json
import logging

# Setup Logging untuk mencatat aktivitas server
logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Penyimpanan klien dan antrian pesan
clients = {}
queued = {}

# Kunci untuk autentikasi klien (misalnya, token atau password)
valid_credentials = {
    "A": "passwordA",
    "B": "passwordB"
}

def safe_send(conn, obj):
    """Mengirim JSON dengan aman."""
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
        queued[target].append(msg)

def flush_queue(role):
    """Mengirim semua pesan yang sebelumnya ditahan."""
    if role not in clients or not clients[role]:
        return
    for msg in queued.get(role, []):
        safe_send(clients[role], msg)
    queued[role] = []

def extract_json_packets(buffer):
    """Mengambil JSON dari stream TCP yang mungkin pecah atau tergabung."""
    packets = []
    brace = 0
    start = None

    for i, ch in enumerate(buffer):
        if ch == '{':
            if brace == 0:
                start = i
            brace += 1
        elif ch == '}':
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
    """Autentikasi klien berdasarkan username dan password."""
    # Menerima data autentikasi (username + password)
    try:
        auth_data = conn.recv(1024)
        auth_json = json.loads(auth_data.decode())
        username = auth_json.get("username")
        password = auth_json.get("password")

        # Cek kredensial
        if valid_credentials.get(username) == password:
            safe_send(conn, {"status": "authenticated"})
            logging.info(f"[SERVER] {role} terautentikasi")
            return True
        else:
            safe_send(conn, {"status": "unauthorized"})
            logging.warning(f"[SERVER] {role} gagal autentikasi")
            return False
    except Exception as e:
        logging.error(f"Kesalahan autentikasi: {e}")
        return False

def handle_client(conn, role):
    """Menangani komunikasi dengan klien."""
    print(f"[SERVER] {role} connected")
    buffer = b""

    # Autentikasi klien
    if not authenticate_client(conn, role):
        conn.close()
        return

    # Simpan klien
    clients[role] = conn
    queued[role] = []

    # Kirim pesan tertunda jika ada
    flush_queue(role)

    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break

            buffer += data
            packets, buffer = extract_json_packets(buffer)

            for packet in packets:
                try:
                    msg = json.loads(packet.decode())
                except Exception as e:
                    logging.error(f"Kesalahan parsing JSON: {e}")
                    continue

                # Proses pesan berdasarkan tipe
                if msg.get("type") == "chat":
                    if role == "A":
                        deliver_or_queue("B", msg)
                    else:
                        deliver_or_queue("A", msg)
                elif msg.get("type") == "des_key" and role == "A":
                    deliver_or_queue("B", msg)
                elif msg.get("type") == "pubkey" and role == "B":
                    deliver_or_queue("A", msg)
                    
        except Exception as e:
            logging.error(f"Kesalahan saat menerima data dari {role}: {e}")
            break

    # Cleanup setelah koneksi ditutup
    print(f"[SERVER] {role} disconnected")
    clients[role] = None
    conn.close()

def main():
    """Server utama untuk menangani koneksi."""
    print("===== SERVER KI (Versi Full Stabil) =====")
    port = int(input("Masukkan port server: "))

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)

    logging.info(f"[SERVER] Berjalan di port {port}...\nMenunggu Client A dan B...")

    while True:
        conn, addr = server.accept()
        role = conn.recv(1024).decode().strip()

        if role not in ("A", "B"):
            conn.close()
            continue

        # Set koneksi klien
        threading.Thread(target=handle_client, args=(conn, role), daemon=True).start()

if __name__ == "__main__":
    main()
