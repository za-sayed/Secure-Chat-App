import sqlite3
import bcrypt

def init_db():
    conn = sqlite3.connect('chat_app.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT
    )
    ''')
    conn.commit()
    conn.close()


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode(), hashed_password)

def register_user(username, password):
    hashed_password = hash_password(password)
    try:
        conn = sqlite3.connect('chat_app.db')
        cursor = conn.cursor()
        
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        print("Username already exists.")
        return False
    finally:
        conn.close()

def user_login(username, password):
    try:
        conn = sqlite3.connect('chat_app.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        if result and check_password(result[0], password):
            return True
        else:
            return False
    finally:
        conn.close()

init_db()
