from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secret_key_here"

# In-memory "database for storing Username, Password, and public key"
users = {}

# In-memory "database for storing chats Structure idea:"
#conversations = {
#    "anoop": {
#        "pranav": {
#            "aes_key_for_anoop": "...",
#            "aes_key_for_pranav": "...",
 #           "messages": [
 #                         "sender": "anoop",
 #                         "message": "ENCRYPTED_BASE64"  
 #                          ...
 #                          ...
 #                          ...
#                        ]
 #       }
 #   }
#}
conversations = {}


# SIGNUP
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data['username']
    password = data['password']
    public_key = data['public_key']

    if username in users:
        return jsonify({"status": "fail", "message": "Username already taken"})

    users[username] = {
        "password": password,
        "public_key": public_key
    }

    return jsonify({"status": "success", "message": "Account created successfully"})


# LOGIN
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    if username in users and users[username]["password"] == password:
        session['username'] = username
        return jsonify({"status": "success", "message": f"Access granted. Welcome {username}"})
    
    return jsonify({"status": "fail", "message": "Access denied"})



#home page
#gets the chat and sends them to the user
@app.route('/conversations')
def get_conversations():
    if 'username' not in session:
        return jsonify({"status": "fail", "message": "Not logged in"})

    username = session['username']

    user_convos = []
    if username in conversations:
        user_convos = list(conversations[username].keys())

    return jsonify({
        "status": "success",
        "conversations": user_convos
    })


#home page
#Starts a new chat between 2 users
@app.route('/start_chat', methods=['POST'])
def start_chat():
    if 'username' not in session:
        return jsonify({"status": "fail", "message": "Not logged in"})

    data = request.json
    user1 = session['username']
    user2 = data['username']

    if user2 not in users:
        return jsonify({"status": "fail", "message": "User does not exist"})

    # Initialize both sides
    conversations.setdefault(user1, {})
    conversations.setdefault(user2, {})

    if user2 in conversations[user1]:
        return jsonify({"status": "fail", "message": "Chat already exists"})

    # Store encrypted AES keys
    conversations[user1][user2] = {
        "aes_key": data["aes_key_user1"],
        "messages": []
    }

    conversations[user2][user1] = {
        "aes_key": data["aes_key_user2"],
        "messages": []
    }

    return jsonify({"status": "success", "message": "Chat created"})



#home page
#For creating a new chat sends the public keys of both users
@app.route('/get_public_keys', methods=['POST'])
def get_keys():
    if 'username' not in session:
        return jsonify({"status": "fail"})

    data = request.json
    other = data['username']
    me = session['username']
    

    if other not in users:
        return jsonify({"status": "fail", "message": "User does not exist"})

    return jsonify({
        "status": "success",
        "my_public_key": users[me]["public_key"],
        "their_public_key": users[other]["public_key"]
    })










#chat page
#gets messages and sends them to the user (still encrypted)
@app.route('/get_messages', methods=['POST'])
def get_messages():
    if 'username' not in session:
        return jsonify({"status": "fail", "message": "Not logged in"})

    data = request.json
    user1 = session['username']
    user2 = data['username']

    if user1 not in conversations or user2 not in conversations[user1]:
        return jsonify({"status": "fail", "message": "No conversation"})

    return jsonify({
        "status": "success",
        "messages": conversations[user1][user2]["messages"]
    })



#chat page
#gets the aes key that encrypted the messages and that is encrypted with that users public key
@app.route('/get_aes_key', methods=['POST'])
def get_aes_key():
    if 'username' not in session:
        return jsonify({"status": "fail"})

    data = request.json
    user1 = session['username']
    user2 = data['username']

    if user2 not in conversations[user1]:
        return jsonify({"status": "fail"})

    return jsonify({
        "status": "success",
        "aes_key": conversations[user1][user2]["aes_key"]
    })

#chat page
#Puts the message receved from user into the conversations variable correctly
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({"status": "fail"})

    data = request.json
    sender = session['username']
    receiver = data['username']
    encrypted_msg = data['message']

    msg_obj = {
        "sender": sender,
        "message": encrypted_msg
    }

    conversations[sender][receiver]["messages"].append(msg_obj)
    conversations[receiver][sender]["messages"].append(msg_obj)

    return jsonify({"status": "success"})











# LOGOUT
@app.route('/logout')
def logout():
    session.pop('username', None)
    return jsonify({"message": "Logged out"})
#source venv/bin/activate
#https://corinna-hymnological-unlearnedly.ngrok-free.dev
#ngrok http 5000
#source venv/bin/activate


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
