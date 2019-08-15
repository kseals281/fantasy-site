from flask import Flask, escape, url_for, render_template, request, redirect
from flask import make_response, session
from pymongo import MongoClient
import hashlib
import os

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY')

client = MongoClient()

db = client.test_database

@app.route('/', methods=['POST', 'GET'])
def index():
  if 'username' in session:
    username = session['username']
  print('Logged in as %s' % escape(session['username']))
  return render_template('indexpy.html', name=username)

@app.route('/register', methods=['POST', 'GET'])
def create_account():
  accounts = db.accounts
  if request.method == 'POST':
    username = request.values.get('username')
    password = request.values.get('password')
    repeated_password = request.values.get('repeatpassword')
    if check_for_username(username):
      return render_template('register.html', usernameTaken=True)
    if password != repeated_password:
      return render_template('register.html', passwords_dont_match=True)
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    new_account = {
      'username': username,
      'password': hashed_password
    }
    accounts.insert_one(new_account).inserted_id
    session['username'] = username
    return redirect(url_for('profile'))
  return render_template('register.html', usernameTaken=False)

def check_for_username(username):
  accounts = db.accounts
  if accounts.find({'username': username}).count() == 0:
    return False
  return True

@app.route('/login', methods=['POST', 'GET'])
def login():
  if request.method == 'POST':
    username = request.values.get('username')
    password = request.values.get('password')
    if not check_for_username(username):
      return render_template('login.html', firstattempt=False)
    if verify_login(username, password):
      session['username'] = username
      return redirect(url_for('profile'))
    return render_template('login.html', firstattempt=False)
  else:
    return render_template('login.html', firstattempt=True)

def verify_login(username, password):
  # Check against db for user and pass
  accounts = db.accounts

  account_to_verify = accounts.find_one({'username': username})
  hashed_password = hashlib.sha256(password.encode()).hexdigest()
  if account_to_verify['password'] == hashed_password:
    return True
  return False

@app.route('/profile')
def profile():
  if 'username' not in session:
    return redirect(url_for('login'))
  username = session['username']
  return render_template('profile.html', name=username)

def check_login():
  username = request.cookies.get('user')
  if username == None:
    return None
  return username

@app.route('/reset')
def reset():
  accounts = db.accounts
  accounts.delete_many({'username': 'foo'})
  return redirect(url_for('create_account'))

if __name__ == '__main__':
    app.run(debug=True)