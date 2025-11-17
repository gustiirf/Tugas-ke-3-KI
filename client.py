import threading
import socket
import RSA
import DES
import sys
import secrets

rsa_crypto = RSA.rsa()
des_crypto = DES.des()
user_cache = {}
AUTH_HOST = "127.0.0.1"
AUTH_PORT = 5000
ADDR = "0.0.0.0"
authority_pu = None
my_pu, my_pr = RSA.generateKeyPair()

def parse(data):
    parts = data.split("|")
    if len(parts) != 4:
        raise ValueError("Invalid data format from authority")
    e = int(parts[0])
    n = int(parts[1])
    ip = parts[2]
    port = int(parts[3])
    return (e, n), ip, port

def recvExact(conn, n):
    data = b""
    while len(data) < n:
        packet = conn.recv(n-len(data))
        if not packet:
            return None
        data += packet
    return data

def listener_init(PORT):
    socket_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_listener.bind((ADDR, PORT))    
    socket_listener.listen()
    
    print(f"[Responder:{PORT}] Ready to receive message...")
    
    while True:
        try:
            conn, addr = socket_listener.accept()
            print(f"[Responeder] Connection accepted form {addr[0]}:{addr[1]}")
            handler_thread = threading.Thread(target=handle_incoming_conn, args=(conn, my_pr))
            handler_thread.start()
        except Exception as e:
            print(f"[Responder] Error: {e}")
            

def handle_incoming_conn(conn, my_key):
    try:
        encrypted_des_key = recvExact(conn, 256)
        des_key_int = RSA.byteToInt(encrypted_des_key)
        print(f"[HANDLER] Decrypting DES...")
        des_key_str = rsa_crypto.decrypt(des_key_int, my_key)
        des_key_str = des_key_str.zfill(64)
        
        round_keys = des_crypto.keySchedule(des_key_str)
        decrypted_bin = ""

        while True:
            encrypted_hex = recvExact(conn, 16)
            if not encrypted_hex:
                break
            
            encrypted_hex = encrypted_hex.decode("utf-8")
            encrypted_bin = DES.hexToBin(encrypted_hex)
                
            plain_block = des_crypto.decrypt(encrypted_bin, round_keys)
            decrypted_bin += plain_block
            
        print(f"[HANDLER] Binary received: {decrypted_bin}")
        unpadded_bin = DES.removePadding(decrypted_bin)
            
        msg = DES.binToASCII(unpadded_bin)
            
            
        print(f"\n[NEW MESSAGE] {msg}")
            
    except Exception as e:
        print(f"[HANDLER] Error while receiving message: {e}")
    finally:
        conn.close()
    
def send_messages(pu_key_target, ip_target, port_target, msg):
    session_key = DES.generateRandomKey()
    round_keys = des_crypto.keySchedule(session_key)
    msg_bin = DES.ASCIItoBin(msg)
    
    padded_bin = DES.addPadding(msg_bin)
    
    block_list = DES.splitBlocks(padded_bin)
    des_key_encrypted = rsa_crypto.encrypt(session_key, pu_key_target)
    des_key_bytes = RSA.intToByte(des_key_encrypted)
    
    socket_target = socket.create_connection((ip_target, port_target))
    socket_target.send(des_key_bytes)
    
    for blocks in block_list:
        encrypted_bin_block = des_crypto.encrypt(blocks, round_keys)
        encrypted_hex_block = DES.binToHex(encrypted_bin_block)
        socket_target.send(encrypted_hex_block.encode("utf-8"))
    
    socket_target.close()
    
def initiate_chat():
    username = input("Who to send: ")
    msg = input("Isi pesannya: ") 
    
    print(f"Request sent")
    target_info = get_user_authority(username)
    print("Key received. Start sending messages...")
    send_messages(target_info.pu_key, target_info.ip, target_info.port, msg)
    print("Message sent")
    
def get_user_authority(username):
    if username in user_cache:
        return user_cache[username]
    
    auth_sock = socket.create_connection((AUTH_HOST, AUTH_PORT))
    try:
        auth_sock.send(f"GETKEY {username}".encode("utf-8"))
        cert = auth_sock.recv(8192)
    finally:
        auth_sock.close()

    if b"||" not in cert:
        raise ValueError("Invalid certificate format")
    payload_bytes, sig_bytes = cert.split(b"||", 1)
    data_target = payload_bytes.decode("utf-8")
    sign_int = int(sig_bytes.decode("utf-8"))

    if authority_pu is None:
        raise RuntimeError("authority_pu not configured in client")

    if not rsa_crypto.verify(data_target, sign_int, RSA.PU(authority_pu[0], authority_pu[1])):
        raise ValueError("Authority signature invalid")

    pu_target, ip_target, port_target = parse(data_target)
    info = (pu_target, ip_target, port_target)
    user_cache[username] = info
    return info

def main_menu_loop():
    print("Type 'send' to send message, 'quit' to exit.")
    while True:
        cmd = input("> ").strip().lower()
        if cmd == "send":
            initiate_chat()
        elif cmd == "quit" or cmd == "exit":
            print("Bye")
            break
        else:
            print("Unknown command. Use 'send' or 'quit'.")

def main():
    if len(sys.argv) != 3:
        print("Usage: python client.py Username Port")
        sys.exit(1)
    my_username = sys.argv[1]
    my_port = int(sys.argv[2])
    
    listener = threading.Thread(target=listener_init, args=(my_port,), daemon=True)
    listener.start()
    
    main_menu_loop()
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python client.py Username Port")
        sys.exit(1)
    main()