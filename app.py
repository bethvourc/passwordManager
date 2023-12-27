from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.fernet import Fernet
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

key_file = 'key.key'
database_file = 'database.db'

if not os.path.exists(key_file):
    key = Fernet.generate_key()
    with open(key_file, 'wb') as key_file:
        key_file.write(key)

with open(key_file, 'rb') as key_file:
    key = key_file.read()

cipher_suite = Fernet(key)

def encrypt_password(password):
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

def decrypt_password(encrypted_password):
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    return decrypted_password

def connect_db():
    return sqlite3.connect(database_file)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and user[2] == encrypt_password(password):
        session['username'] = username
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid username or password', 'error')
        return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM passwords WHERE username = ?", (session['username'],))
        passwords = cursor.fetchall()
        conn.close()
        return render_template('dashboard.html', passwords=passwords)
    else:
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/add_password', methods=['POST'])
def add_password():
    website = request.form['website']
    username = request.form['username']
    password = encrypt_password(request.form['password'])

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)",
                   (website, username, password))
    conn.commit()
    conn.close()

    flash('Password added successfully', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
