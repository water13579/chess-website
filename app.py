from flask import (
    Flask, render_template, jsonify, session, request, g, redirect, url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from flask_socketio import SocketIO, emit, send
import json
import re
from itsdangerous import URLSafeTimedSerializer
import smtplib
import ssl
import os
    
app = Flask(__name__)

app.config['SECRET_KEY'] = 'SECRET'
app.config['EMAIL_USERNAME'] = 'shapira.matan@gmail.com'
app.config['EMAIL_PASSWORD'] = os.environ['EMAIL_PASSWORD']


def get_cursor_db():
    if 'db' not in g:
        g.db = sqlite3.connect('sqlitedb.db')
        g.db.row_factory = sqlite3.Row
    return g.db.cursor() 

def close_db():
    if 'db' in g:
        g.db.close()

def close_and_commit_db():
    if 'db' in g:
        g.db.commit()
        g.db.close()
        
def validate_password(password, repeat_password):
    if password != repeat_password:
        flash('Passwords do not match.')
    elif len(password) < 6:
        flash('Password must contain at least six characters.')
    elif not re.search('[0-9]', password):
        flash('Password must contain at least one digit.')
    elif not re.search('[a-z]', password):
        flash('Password m]ust contain at least one non-capital letter.')
    elif not re.search('[A-Z]', password):
        flash('Password must contain at least one Capital letter.')
    else:
        return True
    return False 

def send_confirmation_mail(email_address):
    serializer = URLSafeTimedSerializer('secret_key')
    token = serializer.dumps(email_address)
    confirm_route = f'http://localhost:5000/confirm/{token}'
    
    smtp_server = 'smtp.gmail.com'
    port = 465
    context = ssl.create_default_context()
    message = f'''
    Subject: Email Confirmation

    <a href={confirm_route}>Hi, please click on this link to confirm your email!</a>
    '''
    print(app.config.get('EMAIL_USERNAME'), app.config.get('EMAIL_PASSWORD'))
    with smtplib.SMTP_SSL(smtp_server, port) as server:
        server.login(app.config.get('EMAIL_USERNAME'), app.config.get('EMAIL_PASSWORD'))
        server.sendmail('shapira.matan@gmail.com', email_address, message)
    

@app.route('/')
@app.route('/index')
def index():
    return 'index page'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        c = get_cursor_db()
        user_data = c.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        close_db()
        if user_data and check_password_hash(user_data['password_hash'], password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        repeat_password = request.form.get('repeat_password')
        email = request.form.get('email')
        c = get_cursor_db()
        username_exists = c.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        email_exists = False #c.execute(' SELECT * FROM users WHERE email=?', (username,)).fetchone()
        if username_exists or email_exists or not validate_password(password, repeat_password):
            if username_exists or email_exists:
                flash('This username is already token!' if username_exists else 'This email is already in use!')
            return redirect(url_for('register'))
        hashed = generate_password_hash(password) 
        c.execute('INSERT INTO users(username, password_hash, email) VALUES (?, ?, ?)', (username, hashed, email))
        close_and_commit_db()
        send_confirmation_mail(email)
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/confirm/<token>')
def confirm_email(token):
    serializer = URLSafeTimedSerializer('secret_key')
    try:
        email = serializer.loads(token)
    except:
        return redirect(url_for('index'))
    c = get_cursor_db()
    c.execute('UPDATE users SET confirmed=? WHERE email=?', (True, email))
    close_and_commit_db()
    return redirect(url_for('index'))


@app.route('/test/inspect_users')
def inspect_users():
    c = get_cursor_db()
    q = c.execute('SELECT * FROM users').fetchall()
    close_db()
    q = [dict(row) for row in q]
    return jsonify(q)
    
    
if __name__ == '__main__':
    app.run(debug=True)