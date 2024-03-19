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

