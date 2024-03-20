from flask import request, jsonify


public_keys = {}

def setup_key_exchange_routes(app):
    @app.route('/submit_public_key/<user_id>', methods=['POST'])
    def submit_public_key(user_id):
        public_key = request.data.decode('utf-8')
        public_keys[user_id] = public_key
        return jsonify({"message": "Public key submitted successfully."})


    @app.route('/get_public_key/<user_id>', methods=['GET'])
    def get_public_key(user_id):
        public_key = public_keys.get(user_id)
        if public_key:
            return jsonify({"public_key": public_key})
        else:
            return jsonify({"error": "Public key not found."}), 404


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
