from flask import Flask, render_template, request, session,redirect, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.secret_key = 'mykey@9696'

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL
                )
                ''')
    conn.commit()
    conn.close()
    
def insert_dummy_user():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?,?)",("admin","12345"))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
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
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password FROM users WHERE username = ?",(username,))
        result = cursor.fetchone()
        
        if result and check_password_hash(result[0],password):
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
def dashboard():
    if 'username' in session:
        return f'''<h2>Welcome {session["username"]}!</h2>
        <a href="/logout">Logout</a>
        '''
    else:
        return redirect(url_for('home'))
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        hashed_password = generate_password_hash(password)
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute("INSERT INTO users (username, password) values (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            return f'user {username} registered successfully!'
        except sqlite3.IntegrityError:
            return 'Username already exists. Try a different one.'
        finally:
            conn.close()
        
    return render_template('register.html')
    
if __name__ == '__main__':
    init_db()
    insert_dummy_user()
    app.run(debug=True)