from flask import Flask, render_template, request, session,redirect, url_for, flash
from functools import wraps
from datetime import timedelta
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.secret_key = 'mykey@9696'
app.permanent_session_lifetime = timedelta(seconds=10)

email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'

def login_required(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Session Expired. Please Login again!", "warning")
            return redirect(url_for('home'))
        return view_func(*args, **kwargs)
    return decorated_function

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL
                )
                ''')
    conn.commit()
    conn.close()

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    remember = request.form.get('remember')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password FROM users WHERE username = ?",(username,))
        result = cursor.fetchone()
        
        if result and check_password_hash(result[0],password):
            if remember:
                session.permanent = True
            else:
                session.permanent = False
            session['username'] = username
            
            flash("Login Successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials", "danger")
            return redirect(url_for('home'))
    except sqlite3.IntegrityError:
        return 'Database error occurred.'
    finally:
        conn.close()
        
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been Logged out", "info")
    return redirect(url_for('home'))
        
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'])
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not email or not username or not password:
            flash("All fields are required", "danger")
            return redirect(url_for('register'))
        
        if not re.match(email_regex, email):
            flash("Please enter a valid email address", "danger")
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute("INSERT INTO users (email, username, password) values (?, ?, ?)", (email, username, hashed_password))
            conn.commit()
            conn.close()
            flash(f'user {username} registered successfully! Please Log in', "success")
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            return 'Username already exists. Try a different one.'
        finally:
            conn.close()
        
    return render_template('register.html')

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.route('/boom')
def boom():
    raise Exception("Testing 500 Error")
    
if __name__ == '__main__':
    init_db()
    app.run()