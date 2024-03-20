# -*- coding: utf-8 -*-
# ==============================================================================
# Copyright (c) 2024 Xavier de Carné de Carnavalet
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ==============================================================================

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash
from flask_mysqldb import MySQL
from flask_session import Session
import yaml
from flask_bcrypt import Bcrypt



app = Flask(__name__)

# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type

# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db_config['mysql_host']
app.config['MYSQL_USER'] = db_config['mysql_user']
app.config['MYSQL_PASSWORD'] = db_config['mysql_password']
app.config['MYSQL_DB'] = db_config['mysql_db']

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
    error = None
    if request.method == 'POST':
        userDetails = request.form
        username = userDetails['username']
        password = userDetails['password']
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id, password FROM users WHERE username = %s", [username])
        account = cur.fetchone()
        
        if account and bcrypt.check_password_hash(account[1], password):
            session['username'] = username
            session['user_id'] = account[0]
            return redirect(url_for('index'))
        else:
            error = 'Invalid username or password'
        cur.close()

    return render_template('login.html', error=error)



@app.route('/recover', methods=['GET', 'POST'])
def recover_account():

# If implementing account recovery, use security questions to verify user identity before allowing password reset.
    
    pass

@app.route('/ecdh')
def ecdh_demo():
    return render_template('ecdh.html')


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

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO users (username, password, public_key) VALUES (%s, %s, %s)", 
                        (username, hashed_password, public_key))
            mysql.connection.commit()
            flash('Registration successful! Please login.', 'success')
        except Exception as e:
            flash(str(e), 'danger')  # Handle errors like duplicate username
        finally:
            cur.close()

        return redirect(url_for('login'))


@app.route('/update_public_key', methods=['POST'])
def update_public_key():
    if 'user_id' not in session:
        return jsonify({'error': 'User not authenticated'}), 403

    user_id = session['user_id']
    public_key = request.json.get('public_key')
    if not public_key:
        return jsonify({'error': 'No public key provided'}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET public_key=%s WHERE user_id=%s", (public_key, user_id))
        mysql.connection.commit()
        return jsonify({'success': 'Public key updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/get_public_key/<username>', methods=['GET'])
def get_public_key(username):
    cur = mysql.connection.cursor()
    cur.execute("SELECT public_key FROM users WHERE username = %s", [username])
    result = cur.fetchone()
    if result:
        return jsonify({'public_key': result[0]})
    else:
        return jsonify({'error': 'User not found'}), 404


    public_keys = {}


bcrypt = Bcrypt(app)
#setup_key_exchange_routes(app)

if __name__ == '__main__':
    app.run(debug=True)

