from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.debug = True

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE,
                        password TEXT
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER,
                        service TEXT,
                        username TEXT,
                        password TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )''')
    conn.close()

init_db()

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid credentials'
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM passwords WHERE user_id = (SELECT id FROM users WHERE username = ?)', (session['username'],))
    passwords = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', passwords=passwords)

@app.route('/add', methods=['GET', 'POST'])
def add():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        service = request.form['service']
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO passwords (user_id, service, username, password) VALUES ((SELECT id FROM users WHERE username = ?), ?, ?, ?)', 
                       (session['username'], service, username, password))
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))
    return render_template('add.html')

@app.route('/edit/<int:password_id>', methods=['GET', 'POST'])
def edit(password_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM passwords WHERE id = ?', (password_id,))
    password = cursor.fetchone()  # Fetch single row, returns tuple or None if not found
    
    if not password:
        return 'Password not found'
    
    password_dict = {
        'id': password[0],
        'user_id': password[1],
        'service': password[2],
        'username': password[3],
        'password': password[4]
    }
    
    if request.method == 'POST':
        service = request.form['service']
        username = request.form['username']
        password_value = request.form['password']
        cursor.execute('UPDATE passwords SET service=?, username=?, password=? WHERE id=?',
                       (service, username, password_value, password_id))
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))
    
    conn.close()
    return render_template('edit.html', password=password_dict)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)