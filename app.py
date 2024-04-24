from flask import Flask, render_template, request, redirect, url_for
import qrcode
from io import BytesIO
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad  # Import the pad function for padding
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
from urllib.parse import urljoin

app = Flask(__name__)

# Unique name for the website
WEBSITE_URL = "https://vishv1234.pythonanywhere.com/"

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        message = request.form['message']
        password = request.form['password']

        # Generate a salt
        salt = os.urandom(16)

        # Derive the key from password and salt
        key = PBKDF2(password, salt, dkLen=32)

        # Pad the message before encryption
        padded_message = pad(message.encode(), AES.block_size)

        # Encrypt message
        cipher = AES.new(key, AES.MODE_CBC, salt)
        ct_bytes = cipher.encrypt(padded_message)
        iv = cipher.iv

        # Encode encrypted message, salt, and IV
        encoded_data = iv + salt + ct_bytes

        # Construct the decryption page URL
        decryption_url = urljoin(request.url_root, '/decrypt')

        # Encode the decryption URL and encrypted data into the QR code
        qr = qrcode.make(f"{decryption_url}?encrypted_data={encoded_data.hex()}")

        # Convert QR code image to base64 for displaying in HTML
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        qr_image = base64.b64encode(buffered.getvalue()).decode('utf-8')

        return render_template('home.html', qr_image=qr_image, website_name=WEBSITE_URL)

    return render_template('home.html', website_name=WEBSITE_URL)



@app.route('/redirect', methods=['GET'])
def redirect_to_website():
    # Redirect to the dedicated website
    return redirect(url_for('home'), code=302)


@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'GET':
        # Render the decryption form template
        encrypted_data_hex = request.args.get('encrypted_data', '')
        return render_template('decrypted.html', encrypted_data=encrypted_data_hex)

    elif request.method == 'POST':
        # Get encrypted data and password from the form
        encrypted_data_hex = request.form['encrypted_data']
        password = request.form['password']

        # Decode hex-encoded data
        encrypted_data = bytes.fromhex(encrypted_data_hex)

        # Extract IV, salt, and ciphertext
        iv = encrypted_data[:16]
        salt = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        # Derive the key from password and salt
        key = PBKDF2(password, salt, dkLen=32)

        try:
            # Decrypt message
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')

            # Pass the decrypted message to the decryption page template
            return render_template('decrypted.html', decrypted_message=decrypted_message)

        except ValueError:
            # If decryption fails (due to wrong password), render template with an error message
            error_message = "Wrong password entered. Please try again."
            return render_template('decrypted.html', error_message=error_message)

if __name__ == '__main__':
    app.run(debug=False)