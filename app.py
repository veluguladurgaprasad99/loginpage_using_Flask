from flask import Flask, render_template, request, redirect, session, flash, jsonify
from flask_mysqldb import MySQL
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = "your_secret_key"

# MySQL Configurations
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '148456'
app.config['MYSQL_DB'] = 'auth_db'
mysql = MySQL(app)

# Flask-Session Configurations
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

@app.route('/')
def home():
    if 'user' in session:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect('/register')

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        existing_user = cur.fetchone()

        if existing_user:
            flash("Email already registered!", "error")
            return redirect('/register')

        hashed_password = generate_password_hash(password)
        cur.execute("INSERT INTO users (fullname, email, password) VALUES (%s, %s, %s)", 
                    (full_name, email, hashed_password))
        mysql.connection.commit()
        cur.close()
        flash("Registration successful! Please login.", "success")
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user[3], password):
            session['user'] = user[1]  # Store user's full name in session
            flash("Login successful!", "success")
            return redirect('/dashboard')
        else:
            flash("Invalid Credentials!", "error")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'])
    flash("Please log in first.", "error")
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully.", "success")
    return redirect('/login')

# API Login Endpoint
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    cur.close()

    if user and check_password_hash(user[3], password):
        return jsonify({"message": "Login successful", "user": user[1]})
    
    return jsonify({"error": "Invalid credentials"}), 401

# Password Reset Route
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect('/reset-password')

        hashed_password = generate_password_hash(new_password)

        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_password, email))
        mysql.connection.commit()
        cur.close()

        flash("Password reset successful! Please login.", "success")
        return redirect('/login')

    return render_template('reset_password.html')

if __name__ == "__main__":
    app.run(debug=True)
