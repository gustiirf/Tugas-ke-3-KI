import hashlib
import secrets
import math

def byteToInt(dataByte):
    return int.from_bytes(dataByte,"big")
    
def intToByte(dataInt):
    byte_len = (dataInt.bit_length() + 7) // 8
    if byte_len == 0:
        byte_len = 1
        
    return dataInt.to_bytes(byte_len, "big")

class PU:
    def __init__(self, e, n):
        self.e = e
        self.n = n

class PR:
    def __init__(self, d, n):
        self.d = d
        self.n = n

def gcdExtended(a, b, x, y):
    if a == 0:
        x[0] = 0
        y[0] = 1
        return b
    
    x1, y1 = [0], [0]
    gcd = gcdExtended(b%a, a, x1, y1)
    
    x[0] = y1[0] - (b//a) * x1[0]
    y[0] = x1[0]
    return gcd

def findGCD(a, b):
    x, y = [1], [1]
    return gcdExtended(a, b, x, y)

def isPrime(n, k=8):
    if n < 2:
        return False
    
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def generatePrime(bits):
    if bits < 2:
        raise ValueError("bits must be >= 2")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if isPrime(candidate):
            return candidate

def modInverse(a,b):
    x, y = [0], [0]
    gcd = gcdExtended(a, b, x, y)
    
    if gcd != 1:
        raise Exception("Modular inverse doesn't exist")
    else: 
        return (x[0] % b + b) % b

def generateKeyPair(bits=2048, e=65537):
    
    if bits < 512:
        raise ValueError("bits too small; use at least 1024 or preferably 2048 for practice")
    
    half = bits // 2
    
    p = generatePrime(half)
    q = generatePrime(bits-half)
    
    n = p*q
    phi_n = (p-1) * (q-1)
    
    d = modInverse(e, phi_n)
    
    print(f"Public key: ({e}, {n})")
    print(f"Private key(do not share): ({d}, {n})")
    
    public_key = PU(e, n)
    private_key = PR(d, n)
    
    return public_key, private_key

class rsa():
    def verify(self, msg, int_sign, pu_send):
        e = pu_send.e
        n = pu_send.n
        
        hash_obj = hashlib.sha256()
        hash_obj.update(msg.encode("utf-8"))
        hash_msg = hash_obj.digest()
        hash_number = byteToInt(hash_msg)
        
        signature_hashed_number = pow(int_sign, e, n)
        
        if hash_number == signature_hashed_number:
            print("Verification succes!")
            return True
        else:
            print("Verification failed!")
            return False
        
    def sign(self, msg, pr):
        d = pr.d
        n = pr.n
        
        hash_obj = hashlib.sha256()
        hash_obj.update(msg.encode("utf-8"))
        hash_msg = hash_obj.digest()
        
        hash_number = byteToInt(hash_msg)
        
        signature_hashed_number = pow(hash_number, d, n)
        return signature_hashed_number
    
    def encrypt(self, msg, pu_recv):
        e = pu_recv.e
        n = pu_recv.n      
        
        bytes_msg = msg.encode("utf-8")
        msg_number = byteToInt(bytes_msg)
        
        if msg_number >= n:
            raise ValueError("The message is to long")
        
        ciphertext_int = pow(msg_number, e, n)
        return ciphertext_int
    
    def decrypt(self, ciphertext_int, pr_recv):
        d = pr_recv.d
        n = pr_recv.n
        
        msg_number = pow(ciphertext_int, d, n)
        
        bytes_msg = intToByte(msg_number)
        bytes_msg = bytes_msg.lstrip(b'\x00')
        string_msg = bytes_msg.decode("utf-8", errors="ignore")
        
        return string_msg

