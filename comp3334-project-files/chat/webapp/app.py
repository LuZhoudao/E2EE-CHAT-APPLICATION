from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash
from flask_mysqldb import MySQL
from flask_session import Session
import yaml
from flask_bcrypt import Bcrypt
from Crypto.Cipher import AES
from helpers import AESencrypt, AESdecrypt, get_totp_uri, verify_totp
from base64 import b64encode, b64decode
import os
import base64
from io import BytesIO
import pyqrcode
import onetimepass

app = Flask(__name__)

# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = b'9\x13\x07j\xf9\x19\xff\x94\xb6\x04\x91\xf31T\x96c'
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type

# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config.update(
    MYSQL_DB=db_config['mysql_db'],
    MYSQL_USER=db_config['mysql_user'],
    MYSQL_PASSWORD=db_config['mysql_password'],
    MYSQL_HOST=db_config['mysql_host']
)
mysql = MySQL(app)

# Initialize the Flask-Session
Session(app)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sender_id = session['user_id']
    return render_template('chat.html', sender_id=sender_id)

@app.route('/users')
def users():
    if 'user_id' not in session:
        abort(403)

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username FROM users")
    user_data = cur.fetchall()
    cur.close()

    filtered_users = [[user[0], user[1]] for user in user_data if user[0] != session['user_id']]
    return {'users': filtered_users}


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id, password FROM users WHERE username = %s", [username])
        account = cur.fetchone()
        
        if account and bcrypt.check_password_hash(account[1], password):
            session['user_id_temp'] = account[0]  # Temporarily store user ID
            session['username_password_verified'] = True
            return redirect(url_for('verify_totp'))  # Redirect to TOTP verification
        else:
            error = 'Invalid username or password or token.'
            flash(error,'danger')
            pass
    # Show login form
    return render_template('login.html')




@app.route('/recover', methods=['GET', 'POST'])
def recover_account():

# If implementing account recovery, use security questions to verify user identity before allowing password reset.
    
    pass

@app.route('/fetch_messages')
def fetch_messages():
    try:
        peer_id = request.args.get('peer_id')
        last_message_id = request.args.get('last_message_id', 0)

        # Fetch messages from the database

        messages = fetch_messages_from_db(peer_id, last_message_id)

        # Return the messages as JSON
        return jsonify({'messages': messages}), 200
    except Exception as e:
        # Log the exception details for debugging
        print(f"Error fetching messages: {e}")
        # Return a JSON error response
        return jsonify({'error': 'Internal Server Error'}), 500

def fetch_messages_from_db(peer_id, last_message_id):
    
    query = """
    SELECT message_id, sender_id, receiver_id, ciphertext, iv, hmac, created_at 
    FROM messages 
    WHERE 
        (sender_id = %s AND receiver_id = %s OR sender_id = %s AND receiver_id = %s) 
        AND message_id > %s
    ORDER BY message_id ASC
    """
    
    values = (session['user_id'], peer_id, peer_id, session['user_id'], last_message_id)
    
    cur = mysql.connection.cursor()
    cur.execute(query, values)
    messages = cur.fetchall()
    cur.close()
    
    return [{
        'message_id': msg[0],
        'sender_id': msg[1],
        'receiver_id': msg[2],
        'ciphertext': msg[3],
        'iv': msg[4],  # Assuming binary data
        'hmac': msg[5],  # Assuming binary data
        'created_at': msg[6].strftime("%Y-%m-%d %H:%M:%S"),
    } for msg in messages]

@app.route('/api/send_message', methods=['POST'])
def send_message():
    # Ensure the request has the necessary encrypted components
    if not request.json or 'ciphertext' not in request.json or 'iv' not in request.json or 'hmac' not in request.json:
        abort(400)  # Bad request if missing any encryption components

    if 'user_id' not in session:
        abort(403)  # Forbidden if the user isn't logged in

    # Extract encrypted data from the request
    sender_id = session['user_id']
    receiver_id = request.json['peer_id'] 
    ciphertext = request.json['ciphertext']
    iv_base64 = request.json['iv']
    hmac_base64 = request.json['hmac']
    

    # simply prints the received data
    print(f"Received encrypted message from {sender_id} to {receiver_id}")
    print(f"Ciphertext: {ciphertext}")
    print(f"IV: {iv_base64}")
    print(f"HMAC: {hmac_base64}")
    
    save_encrypted_message(sender_id, receiver_id, ciphertext, iv_base64, hmac_base64)
    
    return jsonify({'status': 'success', 'message': 'Encrypted message sent'}), 200

def save_encrypted_message(sender_id, receiver_id, ciphertext, iv, hmac):
    try:
        query = '''INSERT INTO messages 
                   (sender_id, receiver_id, ciphertext, iv, hmac) 
                   VALUES (%s, %s, %s, %s, %s)'''
        values = (sender_id, receiver_id, ciphertext, iv, hmac)
        
        cur = mysql.connection.cursor()
        cur.execute(query, values)
        mysql.connection.commit()
        cur.close()
        return True
    except Exception as e:
        print(f"Failed to save message: {e}")
        return False


@app.route('/api/latest_iv/<int:peer_id>')
def get_latest_iv(peer_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Authentication required'}), 403

    try:
        cur = mysql.connection.cursor()
        query = """
            SELECT iv
            FROM messages
            WHERE (sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s)
            ORDER BY message_id DESC
            LIMIT 1
        """
        cur.execute(query, (user_id, peer_id, peer_id, user_id))
        result = cur.fetchone()
        cur.close()

        # If a message is found, return its IV, otherwise return the base64-encoded initial IV
        latest_iv_base64 = result[0] if result else "AAAAAAAAAAAAAAAAAAAAAA=="
        return jsonify({'iv': latest_iv_base64}), 200
    except Exception as e:
        print(f"Error fetching the latest IV: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500



@app.route('/erase_chat', methods=['POST'])
def erase_chat():
    if 'user_id' not in session:
        abort(403)

    peer_id = request.json['peer_id']
    cur = mysql.connection.cursor()
    query = "DELETE FROM messages WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))"
    cur.execute(query, (peer_id, session['user_id'], session['user_id'], peer_id))
    mysql.connection.commit()

    # Check if the operation was successful by evaluating affected rows
    if cur.rowcount > 0:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failure'}), 200


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')  # Flash a logout success message
    return redirect(url_for('index'))
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        # Display the registration form
        return render_template('register.html')
    elif request.method == 'POST':
        print(request.form)
        # Process the form data and register the user
        username = request.form['username']
        password = request.form['password']
        retyped_password = request.form["retyped_password"]
        public_key = request.form['public_key']  # Make sure you have an input for this in your form
        security_question = request.form['securityQuestion']
        security_answer = request.form['securityAnswer']

        if password != retyped_password:
            flash("Different passwords, please input again", 'danger')
            return render_template('register.html')

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # encrypt question and answer
        cur = mysql.connection.cursor()
        cur.execute("SELECT iv FROM users ORDER BY user_id DESC LIMIT 1")
        result = cur.fetchone()
        if result:
            length = len(result[0])
            iv = bytes((int.from_bytes(result[0], byteorder='big')+1).to_bytes(length, byteorder='big'))
        else:
            iv = os.urandom(16)
        cur.close()
        encrypted_question = AESencrypt(app.config['SECRET_KEY'], iv, security_question.encode())
        #decrypted_question = AESdecrypt(app.config['SECRET_KEY'], iv, security_question)
        encrypted_answer = AESencrypt(app.config['SECRET_KEY'], iv, security_answer.encode())
        #decrypted_answer = AESdecrypt(app.config['SECRET_KEY'], iv, security_answer)

        try:
            cur = mysql.connection.cursor()
            totp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
            cur.execute("INSERT INTO users (username, password, security_question, security_answer, public_key, iv, totp_secret) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                        (username, hashed_password, encrypted_question, encrypted_answer, public_key, iv, totp_secret))
            mysql.connection.commit()
            cur.close()
            flash('You are now registered.', 'success')
            session['username'] = username
            return redirect(url_for('qr'))
            #flash('Registration successful! Please login.', 'success')
        except Exception as e:
            flash(str(e), 'danger')  # Handle errors like duplicate username
        # finally:
        #     cur.close()

        return redirect(url_for('login'))


@app.route('/update_public_key', methods=['POST'])
def update_public_key():
    print(request.json)
    # Ensure the user is authenticated
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Authentication required'}), 403

    # Obtain the public key from the request
    public_key = request.json.get('public_key')
    if not public_key:
        return jsonify({'error': 'No public key provided'}), 400

    # Update the user's public key in the database
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET public_key=%s WHERE user_id=%s", (public_key, user_id))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Public key updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500




@app.route('/get_public_key/<user_id>', methods=['GET'])
def get_public_key(user_id):
    
    # Retrieve a user's public key
    cur = mysql.connection.cursor()
    cur.execute("SELECT public_key FROM users WHERE user_id=%s", [user_id])
    result = cur.fetchone()
    cur.close()
    if result:
        return jsonify({'public_key': result[0]})
    else:
        return jsonify({'error': 'User not found'}), 404


@app.route('/qr')
def qr():
    if 'username' not in session:
        return redirect(url_for('register'))
    username = session['username']
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id FROM users WHERE username = %s", [username])
    account = cur.fetchone()
    cur.close()

    if account:
        return render_template('qr.html'), 200, {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'}
    else:
        abort(404)



@app.route('/qr_code')
def qr_code():
    if 'username' not in session:
        return redirect(url_for('register'))
    username = session['username']
    # user = User.query.filter_by(username=username).first()
    # if user is None:
    #     abort(404)

    #del session['username']

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, totp_secret FROM users WHERE username = %s", [username])
    account = cur.fetchone()
    cur.close()
    if account:
        url = pyqrcode.create(get_totp_uri(username, account[1]))
        stream = BytesIO()
        url.svg(stream, scale=5)
        return stream.getvalue(), 200, {
            'Content-Type': 'image/svg+xml',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'}
    else:
        abort(404)

@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot-password.html')

@app.route('/verify_totp', methods=['GET', 'POST'])
def verify_totp():
    if not session.get('username_password_verified'):
        return redirect(url_for('login'))  # Redirect back if the initial check wasn't passed

    if request.method == 'POST':
        user_totp_token = request.form['token']
        user_id_temp = session.get('user_id_temp')

        cur = mysql.connection.cursor()
        cur.execute("SELECT totp_secret FROM users WHERE user_id = %s", [user_id_temp])
        account = cur.fetchone()

        if account and onetimepass.valid_totp(token=user_totp_token, secret=account[0]):
            # TOTP is correct, complete login
            session['user_id'] = user_id_temp  # Now officially logged in
            del session['user_id_temp']  # Clean up
            del session['username_password_verified']
            return redirect(url_for('index'))  # or wherever you want to redirect after login
        else:
            
            pass
    # Show TOTP verification form
    return render_template('verify_totp.html')


#about forgot password
@app.route('/validate-security-info', methods=['POST'])
def validate_security_info():
    ## implement here 

    return redirect(url_for('forgot_password'))

bcrypt = Bcrypt(app)
if __name__ == '__main__':
    app.run(debug=True)

