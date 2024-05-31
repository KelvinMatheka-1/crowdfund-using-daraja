from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import base64
import os
import requests
from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()

# Configurations
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'mysecret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# M-Pesa details
consumer_key = os.getenv('consumer_key')
consumer_secret = os.getenv('consumer_secret')
SHORT_CODE = os.getenv('SHORT_CODE')
PASSKEY = os.getenv('PASSKEY')

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

# Campaign model
class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    target_amount = db.Column(db.Float, nullable=False)
    current_amount = db.Column(db.Float, default=0.0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@app.route('/home')
def home():
    campaigns = Campaign.query.all()
    return render_template('index.html', campaigns=campaigns)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/create_campaign', methods=['GET', 'POST'])
@login_required
def create_campaign():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        target_amount = request.form.get('target_amount')
        campaign = Campaign(title=title, description=description, target_amount=target_amount, user_id=current_user.id)
        db.session.add(campaign)
        db.session.commit()
        flash('Your campaign has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_campaign.html')

@app.route('/view_campaigns')
def view_campaigns():
    campaigns = Campaign.query.all()
    return render_template('view_campaigns.html', campaigns=campaigns)

# M-Pesa API interaction code
def get_access_token():
    mpesa_auth_url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    response = requests.get(mpesa_auth_url, auth=(consumer_key, consumer_secret))
    response.raise_for_status()
    return response.json()['access_token']

def make_mpesa_request(endpoint, payload):
    access_token = get_access_token()
    headers = {
        "Authorization": "Bearer %s" % access_token,
        "Content-Type": "application/json"
    }
    response = requests.post(endpoint, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()

@app.route('/campaign/<int:campaign_id>', methods=['GET', 'POST'])
def campaign_detail(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    if request.method == 'POST':
        request_json = request.form.to_dict()
        request_json['AccountReference'] = f"Campaign-{campaign_id}"
        request_json['TransactionDesc'] = f"Donation to {campaign.title}"
        return lipa_na_mpesa_online(request_json)
    return render_template('campaign_detail.html', campaign=campaign)

@app.route('/simulate', methods=['POST'])
def lipa_na_mpesa_online():
    request_json = request.get_json()
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode((str(SHORT_CODE) + PASSKEY + timestamp).encode('utf-8')).decode('utf-8')
    # callback_url = url_for('callback', _external=True)  # Generates the full external URL for the callback endpoint
    payload = {
        "BusinessShortCode": SHORT_CODE,
        "Password": password,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": request_json['Amount'],
        "PartyA": 254790523549,
        "PartyB": SHORT_CODE,
        "PhoneNumber": request_json['PhoneNumber'],
        "Timestamp": timestamp,
        "CallBackURL": "https://4765-102-217-4-61.ngrok-free.app/callback",
        "AccountReference": f"Campaign-{request_json['AccountReference']}",
        "TransactionDesc": request_json['TransactionDesc'],
    }
    response = make_mpesa_request("https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest", payload)
    return jsonify(response), 200


@app.route('/callback', methods=['POST'])
def callback():
    data = request.get_json()

    # Check if the transaction was successful
    if data['Body']['stkCallback']['ResultCode'] == 0:
        metadata = data['Body']['stkCallback']['CallbackMetadata']['Item']
        amount = float(next(item['Value'] for item in metadata if item['Name'] == 'Amount'))
        account_reference = next(item['Value'] for item in metadata if item['Name'] == 'AccountReference')
        campaign_id = int(account_reference.split('-')[1])

        campaign = Campaign.query.get(campaign_id)
        if campaign:
            campaign.current_amount += amount
            db.session.commit()
            return jsonify({"ResultCode": 0, "ResultDesc": "Success"}), 200

    return jsonify({"ResultCode": 1, "ResultDesc": "Failed"}), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True, port=5000)
