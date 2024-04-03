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

@app.route('/fetch_messages')
def fetch_messages():
    if 'user_id' not in session:
        abort(403)

    last_message_id = request.args.get('last_message_id', 0, type=int)
    peer_id = request.args.get('peer_id', type=int)
    
    cur = mysql.connection.cursor()
    query = """SELECT message_id,sender_id,receiver_id,message_text FROM messages 
               WHERE message_id > %s AND 
               ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))
               ORDER BY message_id ASC"""
    cur.execute(query, (last_message_id, peer_id, session['user_id'], session['user_id'], peer_id))

    # Fetch the column names
    column_names = [desc[0] for desc in cur.description]
    # Fetch all rows, and create a list of dictionaries, each representing a message
    messages = [dict(zip(column_names, row)) for row in cur.fetchall()]

    cur.close()
    return jsonify({'messages': messages})


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



@app.route('/send_message', methods=['POST'])
def send_message():
    if not request.json or not 'message_text' in request.json:
        abort(400)  # Bad request if the request doesn't contain JSON or lacks 'message_text'
    if 'user_id' not in session:
        abort(403)

    # Extract data from the request
    sender_id = session['user_id']
    receiver_id = request.json['receiver_id']
    message_text = request.json['message_text']

    # Assuming you have a function to save messages
    save_message(sender_id, receiver_id, message_text)
    
    return jsonify({'status': 'success', 'message': 'Message sent'}), 200

def save_message(sender, receiver, message):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO messages (sender_id, receiver_id, message_text) VALUES (%s, %s, %s)", (sender, receiver, message,))
    mysql.connection.commit()
    cur.close()

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
        public_key = request.form['public_key']  # Make sure you have an input for this in your form
        security_question = request.form['securityQuestion']
        security_answer = request.form['securityAnswer']

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # encrypt question and answer
        cipher = AES.new(app.config['SECRET_KEY'], AES.MODE_CBC)
        iv = b64encode(cipher.iv).decode('utf-8')
        encrypted_question = AESencrypt(cipher, security_question.encode())
        #decrypted_question = AESdecrypt(app.config['SECRET_KEY'], iv, security_question)
        encrypted_answer = AESencrypt(cipher, security_answer.encode())
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


@app.route('/api/sendPublicKey', methods=['POST'])
def handle_public_key_submission():
    data = request.get_json()
    public_key = data.get('publicKey')
    # Process the public key (e.g., store in the database)
    return jsonify({'message': 'Public key received successfully'}), 200



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

    username = session['username']
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

bcrypt = Bcrypt(app)
if __name__ == '__main__':
    app.run(debug=True)

