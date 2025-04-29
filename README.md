
# 🔐 AES-Tool

Una herramienta de línea de comandos en Python para **encriptar y desencriptar texto** usando el algoritmo **AES (Advanced Encryption Standard)** con soporte para diferentes modos (CBC, GCM, etc.), emulando el formato de OpenSSL para compatibilidad.

Especialmente util cuando se trabaja con la Libreria CrytoJS con la configuración de AES
por defecto:<br>
**Longitud**: 256 Bytes<br>
**Modo de operación**: CBC (Cipher Block Chaining).<br>
**Padding**: Pkcs7.<br>
**Clave (key)**: Se pasa directamente como un string, pero CryptoJS espera una clave de tipo WordArray. Si la clave no tiene el tamaño adecuado (128, 192 o 256 bits), se deriva internamente usando el algoritmo EVP_BytesToKey de OpenSSL.<br>
**IV (Vector de Inicialización)**: Si no se especifica en la función AES.decrypt(), por lo que se usa el IV por defecto, que en CryptoJS es 0x00000000000000000000000000000000 (16 bytes de ceros).

Cálculo del Key y IV con EVP_BytesToKey (MD5 iterativo):
Se usa MD5 iterativamente para generar los bytes necesarios:
Primera iteración: MD5("secretkey12345") → 16 bytes
Segunda iteración: MD5(Primer MD5 + "secretkey12345") → 16 bytes
(Más iteraciones si es necesario hasta completar clave + IV)
Para AES-256 necesitamos: Clave de 32 bytes y IV de 16 bytes

---

## 🚀 Requisitos

- Python 3.7+
- [`pycryptodome`](https://pypi.org/project/pycryptodome/)
- UV (https://github.com/astral-sh/uv)


## Instalación
```bash
git clone https://github.com/soy-oreocato/AES-Tool.git
cd AES-Tool
curl -Ls https://astral.sh/uv/install.sh | sh
uv venv 
source .venv/bin/activate
uv pip install -r requirements.txt
```

---

## ⚙️ Uso

```bash
python AES-Tool.py --action e -k "clave_secreta" -t "Texto a encriptar"
python AES-Tool.py --action d -k "clave_secreta" -t "<texto_en_base64>"
```

### 🔧 Parámetros

| Bandera        | Descripción                                       |
|----------------|----------------------------------------------------|
| `-action`      | Acción a realizar: `encrypt` o `decrypt`           |
| `-k`           | Clave secreta para encriptar o desencriptar        |
| `-t`           | Texto plano a cifrar o texto cifrado en base64     |
| `-mode`        | (Opcional) Modo AES: `CBC`, `GCM` (por defecto: CBC) |

---

## 🔒 Ejemplo

### Encriptar

```bash
python AES-Tool.py -a e -k "mi_clave_123" -t "Hola mundo"
```

Salida esperada:

```
Texto encriptado (base64):
U2FsdGVkX1+.....
```

### Desencriptar

```bash
python AES-Tool.py -a d -k "mi_clave_123" -t "U2FsdGVkX1+..."
```

---

## 📄 Licencia

Este proyecto es de uso libre con fines educativos.