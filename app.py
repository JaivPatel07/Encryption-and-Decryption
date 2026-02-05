from flask import Flask, render_template, request, jsonify
from cryptography.fernet import Fernet
import base64
import hashlib

app = Flask(__name__)

# Convert user key into valid Fernet key
def generate_key(user_key):
    key = hashlib.sha256(user_key.encode()).digest()
    return base64.urlsafe_b64encode(key)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()
    message = data["message"]
    user_key = data["key"]

    try:
        key = generate_key(user_key)
        f = Fernet(key)

        encrypted = f.encrypt(message.encode())
        return jsonify({"result": encrypted.decode()})
    except:
        return jsonify({"result": "Encryption error"})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json()
    message = data["message"]
    user_key = data["key"]

    try:
        key = generate_key(user_key)
        f = Fernet(key)

        decrypted = f.decrypt(message.encode())
        return jsonify({"result": decrypted.decode()})
    except:
        return jsonify({"result": "Wrong key or invalid data"})

if __name__ == "__main__":
    app.run(debug=True)
