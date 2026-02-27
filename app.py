from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'fluent-secret-key-99'

# Your Database Configuration
DB_CONFIG = {
    "user": "root",
    "password": "root",
    "database": "db",
    "host": "localhost"
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# --- PAGE ROUTES ---
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return render_template('index.html')

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('home.html', username=session.get('username'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# --- API ROUTES ---
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = generate_password_hash(data.get('password'))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
        conn.commit()
        return jsonify({"success": True, "message": "Account created! Please login."}), 201
    except mysql.connector.Error:
        return jsonify({"success": False, "message": "Username already exists."}), 400
    finally:
        cursor.close()
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        return jsonify({"success": True, "message": "Login successful!", "redirect": "/home"})
    
    return jsonify({"success": False, "message": "Invalid credentials."}), 401

if __name__ == '__main__':
    # Auto-create table on start
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(150) UNIQUE, password VARCHAR(255))")
    conn.commit()
    cursor.close()
    conn.close()
    
    app.run(debug=True)