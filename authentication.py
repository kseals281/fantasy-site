from flask import Flask, escape, url_for, render_template, request, redirect
from pymongo import MongoClient
import hashlib

app = Flask(__name__)

client = MongoClient()

db = client.test_database

@app.route('/', methods=['POST', 'GET'])
def index(name=None):
  return render_template('indexpy.html', name=name)

@app.route('/create', methods=['POST', 'GET'])
def create_account():
  accounts = db.accounts
  if request.method == 'POST':
    username = request.values.get('username')
    password = request.values.get('password')
    if check_for_username(username):
      return render_template('register.html', usernameTaken=True)
    hashedPassword = hashlib.sha256(password.encode()).hexdigest()
    new_account = {
      'username': username,
      'password': hashedPassword
    }
    accounts.insert_one(new_account).inserted_id
    return render_template('indexpy.html', user=username)
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
    if verify_login(username, password):
      return render_template('success.html', user=username, message='login')
    return render_template('login.html', firstattempt=False)
  else:
    return render_template('login.html', firstattempt=True)

def verify_login(username, password):
  # Check against db for user and pass
  accounts = db.accounts

  account_to_verify = accounts.find_one({'username': username})

  if account_to_verify['password'] == password:
    return True
  return False

@app.route('/reset')
def reset():
  accounts = db.accounts
  accounts.delete_many({'username': 'foo'})
  return redirect(url_for('create_account'))

if __name__ == '__main__':
    app.run(debug=True)