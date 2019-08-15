from flask import Flask, escape, url_for, render_template, request, redirect
from flask import make_response, session
from pymongo import MongoClient
import hashlib
import os

app = Flask(__name__)

app.secret_key = b'\x80 \xa55\x98/\xba\xa8\xeb\x1ec\xfc\xee5l\xd1'

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
      'password': hashed_password,
      'racer1': None,
      'racer2': None,
      'racer3': None
    }
    accounts.insert_one(new_account).inserted_id
    session['username'] = username
    session['account'] = {
      'racer1': None,
      'racer2': None,
      'racer3': None
    }
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

@app.route('/profile', methods=['POST', 'GET'])
def profile():
  if 'username' not in session:
    return redirect(url_for('login'))
  racers = db.racers
  racers_list = racers.find()
  username = session['username']
  current_user = session['account']
  if request.method == 'POST':
    get_user_racers()
  racer1 = current_user['racer1']
  racer2 = current_user['racer2']
  racer3 = current_user['racer3']
  return render_template(
    'profile.html', name=username, racer1=racer1, racer2=racer2, racer3=racer3,
    runner_list=racers_list)

def get_user_racers():
  racers = db.racers
  racer1 = (request.values.get('racer1')).lower()
  racer2 = (request.values.get('racer2')).lower()
  racer3 = (request.values.get('racer3')).lower()
  runners = [racer1, racer2, racer3]
  print(racers.find({'name': racer2}))
  for runner in runners:
    if runner == racers.find({'name': runner}):
      print("Racer %s not found" % runner)

def check_login():
  if username == None:
    return None
  return username

@app.route('/reset')
def reset():
  accounts = db.accounts
  accounts.delete_many({'username': 'foo'})
  racers = db.racers
  racers.delete_many({})
  return redirect(url_for('create_account'))

@app.route('/upload', methods=['POST', 'GET'])
def upload_race():
  if request.method == 'POST':
    racers = db.racers
    racers.delete_many({})
    for j in range(1, 5):
      for i in range(1, 9):
        team = ('team' + str(j)).lower()
        racer = ('racer' + str(i)).lower()
        name = request.values.get(team+racer)
        current_racer = {
          'team': team,
          'name': name,
        }
        print('Current racer name: %s' % current_racer['name'])
        if current_racer['name'] != '':
          print(current_racer)
          racers.insert_one(current_racer).inserted_id
    return render_template('main.html')
  return render_template('main.html')

if __name__ == '__main__':
    app.run(debug=True)