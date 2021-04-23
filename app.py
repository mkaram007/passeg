from flask import Flask, render_template, url_for, request, redirect, flash, Response, session
import json
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, exc
from datetime import datetime
from flask_login import LoginManager, login_required, current_user, UserMixin, login_user, logout_user
from lib.main_settings import *
import random
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask (__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///records.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/'
login_manager.login_message = "Login required"
login_manager.login_message_category = "warning"
app.config['SECRET_KEY'] = SECRET_KEY 
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(500), nullable= True)
    Username = db.Column(db.String(500), nullable= False, unique=True)
    Master_Password = db.Column(db.String(500), nullable=False)

    def __repr__(self):
        return ("User Created", "info")

@app.route('/signup', methods=['POST','GET'])
def sign_up():
    if current_user.is_authenticated:
        flash ("Logout to register a new user", "Error!")
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['Name']
        username = request.form['Username']
        password = request.form['Password']
        if len(username) == 0 or len(password) == 0:
            return "Inproper username or password"
        username = func.lower(username)
        if User.query.filter_by(Username = username).first():
            flash("This username already exists", "danger")
            return redirect (url_for('sign_up'))

        new_user = User(Name = name, Username = username, Master_Password = generate_password_hash(password, method='sha256'))
        #try:
        db.session.add(new_user)
        db.session.commit()
        flash("User Created Successfully", "info")
        
        return redirect('/')
        #except:
        #    return "There was an issue signing up"
    else:
        return render_template('signup.html')


class Record(UserMixin, db.Model):
    Id = db.Column(db.Integer, primary_key=True)
    Owner_Id = db.Column(db.Integer, nullable=False)
    AccountType = db.Column(db.String(10), nullable=False)
    Name = db.Column(db.String(200), nullable= True)
    Username = db.Column(db.String(500), nullable= False)
    Password = db.Column(db.String(500), nullable= False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    date_modified = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return ("Can't create password", "error")

@app.route('/home', methods=['POST','GET'])
@login_required
def index():
    records = Record.query.order_by(Record.date_created).filter_by(Owner_Id=current_user.get_id())
    return render_template('index.html', records=records)

@app.route('/delete/<int:Id>')
def delete(Id):
    password_to_delete = Record.query.get_or_404(Id)
    try:
        db.session.delete(password_to_delete)
        db.session.commit()
        return redirect('/home')
    except:
        return 'There was a problem deleting this password'

@app.route('/update/<int:Id>', methods=['GET', 'POST'])
def update(Id):
    record_to_update = Record.query.get_or_404(Id)
    if request.method == 'POST':
        record_to_update.AccountType = request.form['account']
        record_to_update.Name = request.form['Name']
        record_to_update.Username = request.form['Username']
        record_to_update.Password = request.form['password']
        record_to_update.date_modified = datetime.utcnow()
        try:
            db.session.commit()
            return redirect('/home')
        except:
            return "There was a problem updating this password"
    else:
        return render_template('update.html', record=record_to_update)

@app.route('/clipboard.min.js')
def js():
    return render_template('clipboard.min.js')

@app.route('/add', methods=['GET','POST'])
@login_required
def add():
    if request.method == 'POST':

        accountType = request.form['account']
        name = request.form['name']
        username = func.lower(request.form['username'])
        password = request.form['password']
        if request.form['username'] == None or password == None:
            alert("Username and password can't be empty", 'danger')
            return redirect(url_for(add))
        Owner_Id = current_user.get_id()
        new_record = Record(AccountType = accountType, Name=name, Username=username, Password=password, Owner_Id=Owner_Id)
        try:
            db.session.add(new_record)
            db.session.commit()
            return redirect('/home')
        except:
            return 'There was an issue adding the new password'
    else:
        return render_template('add.html')

@app.route('/', methods=['POST'])
def signin_post():
    username = func.lower(request.form['Username'])
    password = request.form['Password']
    user = User.query.filter_by(Username = username).first()
    #try:
    if not user or not check_password_hash(user.Master_Password, password):
        flash('Invalid username or password', 'danger')
        return redirect(url_for('login'))

    login_user(user)
    if user.Name:
        session['current_username']='Welcome '+user.Name+'!'
    else:
        session['current_username']='Welcome '+user.Username+'!'

    return redirect(url_for('index'))
    """ 
    except AttributeError:
        flash('Invalid username or password', 'Error!')
        return redirect(url_for('login'))
    """
"""    
@LoginManager.unauthorized_handler
def unauthorized():
    flash ('Login required', 'error')
    return a_response
"""
@app.route('/')
def login():
    return render_template('signin.html')

@app.route('/about')
def about():
    return 'Egirna Technologies'

@app.route('/details/<int:Id>')
def details(Id):
    record_to_update = Record.query.get_or_404(Id)
    return render_template('details.html', record = record_to_update)

@app.route('/random')
def randomGen():
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz!@#$%^&*()*/-+.1234567890{}]['
    password = ''
    for c in range(16):
        password += random.choice(chars)
    return {'password':password}

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash ('Logged out', 'info')
    session['current_username'] = ''
    return redirect('/')

if __name__ == "__main__":
    app.run (port = 8000,debug = True)
