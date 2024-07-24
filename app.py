from flask import Flask, request, render_template, redirect, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from passlib.hash import bcrypt
from flask_mail import Mail, Message
import os
import random
from datetime import timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:Super%40123@localhost:5432/newdatabase')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', '7f3b5d8e4c0a6a9e1d2f6e3b4a7c8d9e0e7f3b2d6a1c9e8f7b4a0c6d3e2f1a9b')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.permanent_session_lifetime = timedelta(days=7)

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'python@networkershome.com'
app.config['MAIL_PASSWORD'] = 'mfgg xusw qofh mpll'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hash(password)

    def check_password(self, password):
        return bcrypt.verify(password, self.password)

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# In-memory storage for OTPs
otp_storage = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash('Email address already exists.')
            return redirect('/register')

        # Generate and store OTP
        otp = random.randint(100000, 999999)
        otp_storage[email] = otp

        # Send OTP via email
        msg = Message('Your OTP Code', sender='python@networkershome.com', recipients=[email])
        msg.body = f'Your OTP code is {otp}'
        mail.send(msg)
        
        session['registration_name'] = name
        session['registration_email'] = email
        session['registration_password'] = password
        
        return redirect('/verify_otp')
    
    return render_template('register.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form.get('otp')
        
        # Retrieve email from session
        email = session.get('registration_email')
        
        if email and otp and otp_storage.get(email) == int(otp):
            # Remove OTP after successful validation
            del otp_storage[email]
            
            # Create the user account
            name = session.get('registration_name')
            password = session.get('registration_password')
            
            if name and password:
                user = User(name=name, email=email, password=password)
                db.session.add(user)
                db.session.commit()
            
            # Clear the session data
            session.pop('registration_name', None)
            session.pop('registration_email', None)
            session.pop('registration_password', None)
            
            flash('OTP verified successfully. You are now registered. Please log in.')
            return redirect('/login')
        else:
            flash('Invalid OTP or email.')
            return redirect('/verify_otp')
    
    # Render form if GET request
    return render_template('verify_otp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = user.email
            session.permanent = True
            flash('Login successful.')
            return redirect('/dashboard')
        else:
            flash('Invalid email or password.')
            return redirect('/login')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        flash('You need to log in first.')
        return redirect('/login')
    
    user = User.query.filter_by(email=session['email']).first()
    return render_template('dashboard.html', user=user)


@app.route('/logout')
def logout():
    session.pop('email', None)
    flash('You have been logged out.')
    return redirect('/login')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        new_password = request.form.get('new_password')

        user = User.query.filter_by(email=email).first()

        if user:
            user.password = bcrypt.hash(new_password)
            db.session.commit()
            flash('Password has been updated.')
            return redirect('/login')
        else:
            flash('Email address not found.')
            return redirect('/reset_password')

    return render_template('reset_password.html')

@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.form.get('email')
    # Generate and store OTP
    otp = random.randint(100000, 999999)
    otp_storage[email] = otp
    
    # Store email in session
    session['registration_email'] = email
    
    # Send OTP to email
    msg = Message('Your OTP Code', sender='python@networkershome.com', recipients=[email])
    msg.body = f'Your OTP code is {otp}'
    mail.send(msg)
    
    flash('OTP sent to your email.')
    return redirect('/verify_otp')

@app.route('/validate_otp', methods=['POST'])
def validate_otp():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    
    if otp_storage.get(email) == int(otp):
        del otp_storage[email]  # Remove OTP after successful validation
        return jsonify({'status': 'OTP validated successfully'})
    else:
        return jsonify({'status': 'Invalid OTP'}), 400

# Create tables before starting the application
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
