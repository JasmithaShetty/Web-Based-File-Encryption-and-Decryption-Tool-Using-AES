from flask import Flask, render_template, request, send_file, jsonify
import io, hashlib, struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)

MAGIC = b'ENCF'   # simple magic header to detect our file format
BLOCK = AES.block_size  # 16

def pkcs7_pad(b: bytes) -> bytes:
    pad_len = BLOCK - (len(b) % BLOCK)
    return b + bytes([pad_len]) * pad_len

def pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        raise ValueError("Empty plaintext")
    pad_len = b[-1]
    if pad_len < 1 or pad_len > BLOCK:
        raise ValueError("Invalid padding")
    if b[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return b[:-pad_len]

def derive_key(password: str) -> bytes:
    # Simple deterministic key derivation: SHA-256 of password -> 32 bytes
    return hashlib.sha256(password.encode()).digest()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    f = request.files.get('file')
    password = request.form.get('password', '')
    if not f or password == '':
        return jsonify({'error': 'file and password required'}), 400

    key = derive_key(password)
    data = f.read()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs7_pad(data))

    filename_bytes = f.filename.encode('utf-8')
    if len(filename_bytes) > 65535:
        return jsonify({'error': 'filename too long'}), 400

    # Pack: MAGIC (4) | name_len(2 BE) | name | iv(16) | ciphertext
    out = MAGIC + struct.pack('>H', len(filename_bytes)) + filename_bytes + iv + ct
    bio = io.BytesIO(out)
    bio.seek(0)
    return send_file(bio,
                     as_attachment=True,
                     download_name=f.filename + '.enc',
                     mimetype='application/octet-stream')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    f = request.files.get('file')
    password = request.form.get('password', '')
    if not f or password == '':
        return jsonify({'error': 'file and password required'}), 400

    raw = f.read()
    key = derive_key(password)

    try:
        # If file has our header, parse it
        if raw[:4] == MAGIC:
            pos = 4
            name_len = struct.unpack('>H', raw[pos:pos+2])[0]; pos += 2
            filename = raw[pos:pos+name_len].decode('utf-8'); pos += name_len
            iv = raw[pos:pos+16]; pos += 16
            ct = raw[pos:]
        else:
            # Fallback: older format (iv + ciphertext) and use incoming filename
            # In that case we cannot recover original filename reliably; use given name.
            filename = f.filename.replace('.enc','_decrypted')
            iv = raw[:16]
            ct = raw[16:]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt_padded = cipher.decrypt(ct)
        pt = pkcs7_unpad(pt_padded)

        bio = io.BytesIO(pt)
        bio.seek(0)
        return send_file(bio,
                         as_attachment=True,
                         download_name=filename,
                         mimetype='application/octet-stream')
    except Exception:
        # Do not reveal internal errors — just say it failed (likely wrong key or corrupted file)
        return jsonify({'error': 'Decryption failed — wrong key or corrupted file.'}), 400

if __name__ == '__main__':
    app.run(debug=True)
