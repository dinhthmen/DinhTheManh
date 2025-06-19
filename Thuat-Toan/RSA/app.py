from flask import Flask, request, render_template, send_from_directory, jsonify
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
import base64

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['KEYS_FOLDER'] = 'keys'

# Tạo thư mục uploads và keys nếu chưa có
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['KEYS_FOLDER'], exist_ok=True)

# --- Chức năng quản lý khóa RSA ---
def generate_rsa_keys(key_name="default"):
    key = RSA.generate(2048)
    private_key_path = os.path.join(app.config['KEYS_FOLDER'], f'{key_name}_private.pem')
    public_key_path = os.path.join(app.config['KEYS_FOLDER'], f'{key_name}_public.pem')

    with open(private_key_path, 'wb') as f:
        f.write(key.export_key('PEM'))
    with open(public_key_path, 'wb') as f:
        f.write(key.public_key().export_key('PEM'))
    return private_key_path, public_key_path

def load_private_key(key_name="default"):
    private_key_path = os.path.join(app.config['KEYS_FOLDER'], f'{key_name}_private.pem')
    if not os.path.exists(private_key_path):
        return None
    with open(private_key_path, 'rb') as f:
        key = RSA.import_key(f.read())
    return key

def load_public_key(key_name="default"):
    public_key_path = os.path.join(app.config['KEYS_FOLDER'], f'{key_name}_public.pem')
    if not os.path.exists(public_key_path):
        return None
    with open(public_key_path, 'rb') as f:
        key = RSA.import_key(f.read())
    return key

# Tạo khóa mặc định khi ứng dụng khởi chạy nếu chưa có
if not os.path.exists(os.path.join(app.config['KEYS_FOLDER'], 'default_private.pem')):
    generate_rsa_keys("default")
    print("Generated default RSA keys.")

# --- API Endpoints ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['POST'])
def generate_new_keys_api():
    key_name = request.form.get('key_name', 'default')
    private_key_path, public_key_path = generate_rsa_keys(key_name)
    return jsonify({
        "message": f"Keys for '{key_name}' generated successfully.",
        "private_key_path": private_key_path,
        "public_key_path": public_key_path
    })

@app.route('/upload_and_sign', methods=['POST'])
def upload_and_sign():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    key_name = request.form.get('key_name', 'default')
    private_key = load_private_key(key_name)
    if not private_key:
        return jsonify({"error": f"Private key for '{key_name}' not found. Please generate it first."}), 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    # Đọc nội dung file để ký
    with open(filepath, 'rb') as f:
        file_content = f.read()

    # Ký số file
    h = SHA256.new(file_content)
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(h)

    # Lưu chữ ký vào file riêng (hoặc nhúng vào metadata của file nếu định dạng cho phép)
    signature_filepath = os.path.join(app.config['UPLOAD_FOLDER'], f'{file.filename}.sig')
    with open(signature_filepath, 'wb') as f:
        f.write(signature)

    return jsonify({
        "message": "File uploaded and signed successfully.",
        "filename": file.filename,
        "signature_filename": f'{file.filename}.sig',
        "signature": base64.b64encode(signature).decode('utf-8') # Trả về chữ ký base64 để frontend tiện hiển thị/kiểm tra
    })

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/verify_signature', methods=['POST'])
def verify_signature():
    if 'file' not in request.files or 'signature_file' not in request.files:
        return jsonify({"error": "Both file and signature file are required"}), 400

    file_to_verify = request.files['file']
    signature_file = request.files['signature_file']
    
    key_name = request.form.get('key_name', 'default')
    public_key = load_public_key(key_name)
    if not public_key:
        return jsonify({"error": f"Public key for '{key_name}' not found. Cannot verify."}), 400

    # Đọc nội dung file gốc
    original_file_content = file_to_verify.read()
    
    # Đọc chữ ký
    signature = signature_file.read()

    # Băm nội dung file
    h = SHA256.new(original_file_content)
    verifier = pkcs1_15.new(public_key)

    try:
        verifier.verify(h, signature)
        return jsonify({"message": "Signature is valid.", "status": "success"})
    except (ValueError, TypeError):
        return jsonify({"message": "Signature is NOT valid.", "status": "failed"})

if __name__ == '__main__':
    app.run(debug=True) # debug=True để tự động reload và hiển thị lỗi, nên tắt khi deploy production