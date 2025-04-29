#!/usr/bin/env python3

from Crypto.Cipher import AES
import base64
import hashlib
import argparse

def evp_bytes_to_key(password: str, salt: bytes, key_size: int = 32, iv_size: int = 16):
    """Deriva clave e IV usando el método EVP_BytesToKey con MD5."""
    key_iv = b""
    prev = b""

    while len(key_iv) < key_size + iv_size:
        prev = hashlib.md5(prev + password.encode() + salt).digest()
        key_iv += prev

    return key_iv[:key_size], key_iv[key_size:key_size + iv_size]

def encrypt_aes(plaintext: str, password: str):
    """Encripta un texto usando AES-256-CBC en formato OpenSSL."""
    # Generar un salt aleatorio de 8 bytes
    salt = hashlib.sha256().digest()[:8]  # Simulación de un salt aleatorio fijo

    # Derivar clave e IV
    key, iv = evp_bytes_to_key(password, salt)

    # Configurar AES en el modo CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Aplicar padding PKCS7
    pad_len = 16 - (len(plaintext) % 16)
    plaintext_padded = plaintext + chr(pad_len) * pad_len

    # Cifrar el texto
    encrypted_data = cipher.encrypt(plaintext_padded.encode())

    # Formato OpenSSL (Salted__ + salt + data)
    encrypted_b64 = base64.b64encode(b"Salted__" + salt + encrypted_data).decode()
    return encrypted_b64

def decrypt_aes(ciphertext_b64: str, password: str):
    """Desencripta un texto cifrado con AES-256-CBC en formato OpenSSL."""
    # Decodificar base64
    ciphertext = base64.b64decode(ciphertext_b64)
    
    # Verificar prefijo de OpenSSL (Salted__)
    if ciphertext[:8] != b"Salted__":
        raise ValueError("Formato de cifrado incorrecto")

    # Extraer salt (8 bytes después del prefijo "Salted__")
    salt = ciphertext[8:16]
    encrypted_data = ciphertext[16:]

    # Derivar clave e IV
    key, iv = evp_bytes_to_key(password, salt)

    # Configurar AES en modo CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Desencriptar y eliminar padding PKCS7
    decrypted = cipher.decrypt(encrypted_data)
    pad = decrypted[-1]
    decrypted = decrypted[:-pad]

    return decrypted.decode('utf-8')

def main():
    parser = argparse.ArgumentParser(description="AES Tool (CBC mode, OpenSSL compatible)")
    parser.add_argument("-a", "--action", required=True, choices=["e", "d"], help="Acción: encrypt o decrypt")
    parser.add_argument("-k", "--key", help="Llave (password)")
    parser.add_argument("-t", "--text", help="Texto plano o cifrado (base64)")
    parser.add_argument("-tf", "--text_file", help="Ruta a archivo de entrada")
    parser.add_argument("-m", "--mode", choices=["CBC"], default="CBC", help="Modo de cifrado (por ahora solo CBC)")

    args = parser.parse_args()

    if args.mode != "CBC":
        print("Solo se soporta CBC por ahora.")
        return

    # Texto: Leer contenido desde archivo si se especifica
    if args.text_file:
        try:
            with open(args.text_file, 'r', encoding='utf-8') as f:
                #Elimina salto de linea al final del archivo
                args.text = f.read().strip() 
        except Exception as e:
            print(f"❌ Error al leer el archivo: {e}")
            return

    # Verificar que hay texto disponible
    if not args.text:
        print("❌ Debes proporcionar texto con -t o un archivo con -f")
        return

    try:
        if args.action == "e":
            encrypted = encrypt_aes(args.text, args.key)
            print(f"\n🔐 Texto cifrado:\n{encrypted}")
        elif args.action == "d":
            decrypted = decrypt_aes(args.text, args.key)
            print(f"\n🔓 Texto descifrado:\n{decrypted}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()

