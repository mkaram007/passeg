import werkzeug
import os
from flask import Flask, render_template, url_for, request, redirect, flash, Response, session
import json
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, exc
from datetime import datetime
from flask_login import LoginManager, login_required, current_user, UserMixin, login_user, logout_user
from lib.main_settings import *
import random
from werkzeug.security import generate_password_hash, check_password_hash
from validate_email import validate_email
from itsdangerous import URLSafeTimedSerializer
#from flask_mail import Message, Mail
#from flask_bcrypt import Bcrypt
import re


success  = lambda resp: {'status':'success','data':resp}
failure  = lambda resp: {'status':'failure','data':resp}



app = Flask (__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///records.db'
db = SQLAlchemy(app)
#mail = Mail(app)
#bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/'
#login_manager.login_message = {'status':'failure','data':"Login required"}
#login_manager.login_message_category = "warning"
app.config['SECRET_KEY'] = SECRET_KEY 
app.config['SECURITY_PASSWORD_SALT'] = SECURITY_PASSWORD_SALT
app.config['MAIL_DEFAULT_SENDER'] = MAIL_DEFAULT_SENDER


@app.errorhandler(404)
def not_found(error):
        #return make_response(jsonify(failure('not found')), 404)
        return failure("Not Found")


@app.errorhandler(401)
def unauthorized(error):
        #return make_response(jsonify(failure('unauthorized')), 401)
        return failure("Login required")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



def generate_confirmation_token(username):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(username, salt=app.config['SECURITY_PASSWORD_SALT'])


def verify_email(username):
    if not re.match(r"[^@]+@[^@]+\.[^@]+", username):
        return False
    return True


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
        token,
        salt=app.config['SECURITY_PASSWORD_SALT'],
        max_age=expiration
        )
    except:
        return False
    return email

def send_email(to, subject, template):
        msg = Message(
            subject,
            recipients=[to],
            html=template,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        mail.send(msg)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(500), nullable= True)
    Username = db.Column(db.String(500), nullable= False, unique=True)
    Master_Password = db.Column(db.String(500), nullable=False)
    Confirmed = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return ("User Created", "info")

@app.route('/getCurrentUser')
def getCurrentUser():
    if current_user.is_authenticated:
        return success(current_user.get_id())
    else:
        return failure("Login required")

@app.route('/editUser', methods = ['POST'])
def editUser():
    if current_user.is_authenticated:
        return True


@app.route('/signup', methods=['POST'])
def sign_up():
    if current_user.is_authenticated:
        return failure("Logout to register a new user")
    data = request.json
    name = data.get('Name')
    username = data.get('Username')
    #if len(username.split('@')) == 1 or len(username.split('@')[1].split('.')) ==1:
    if not verify_email(username):
        return failure ("Invalid username, example username: username@example.com")
    password = data.get('Password')
    try:
        if len(username) == 0 or len(password) == 0:
            return failure("Inproper username or password")
    except TypeError:
        return failure("Inproper username or password")
    username = func.lower(username)
    if User.query.filter_by(Username = username).first():
        return failure('This username already exists')

    new_user = User(Name = name, Username = username, Master_Password = generate_password_hash(password, method='sha256'), Confirmed = False)
    db.session.add(new_user)
    db.session.commit()
    user_id = User.query.filter_by(Username = username).first().id
    return success ("Registeration completed with ID: "+ str(user_id))
    '''
    token = generate_confirmation_token(request.form['Username'])
#        try:
    confirm_url = url_for('confirm_email', token=token, _external=True)
#        except werkzeug.routing.BuildError:
#            return token
    html = render_template('activate.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(username, subject, html)
    login_user(new_user)

    flash('A confirmation email has been sent via email.', 'success')

    return redirect('/')
    #except:
    #    return "There was an issue signing up"
    '''


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
"""
@app.route('/home', methods=['POST','GET'])
@login_required
def index():
    records = Record.query.order_by(Record.date_created).filter_by(Owner_Id=current_user.get_id())
    return render_template('index.html', records=records)
"""
@app.route('/delete/<int:Id>', methods=['POST'])
def delete(Id):
    if current_user.is_authenticated:
        password_to_delete = Record.query.get_or_404(Id)
    else:
        return failure ("Login required")
    try:
        db.session.delete(password_to_delete)
        db.session.commit()
        return success (Id)
    except:
        return failure('There was a problem deleting this password')

@app.route('/getPasswordId/<string:username>')
def getPasswordId(username):
    record = Record.query.filter_by(Username = username).first()
    if record:
        return success (record.Id)
    else:
        return failure ("Password not found")

@app.route('/getPasswords')
def getPasswords():
    if not current_user.is_authenticated:
        return failure ("Login required")
    records = Record.query.filter_by(Owner_Id = current_user.get_id())
    recs = []
    for record in records:
        recs.append(str({"id":record.Id, "Name":record.Name, "Username":record.Username, "Password":record.Password}))
    ','.join(recs)
    return success (recs)


@app.route('/update/<int:Id>', methods=['GET', 'POST'])
#@login_required
def update(Id):
    if not current_user.is_authenticated:
        return failure ("Login required")
    record_to_update = Record.query.get_or_404(Id)
    if request.method == 'POST':
        data = request.json
        record_to_update.Name = data.get('Name')
        username = data.get('Username')
        if not verify_email(username):
            return failure ("Invalid username, example username: username@example.com")
        record_to_update.Username = username
        record_to_update.Password = data.get('Password')
        record_to_update.date_modified = datetime.utcnow()
        try:
            db.session.commit()
            return success("Password has been updated successfully")
        except:
            return failure ("There was a problem updating this password")
    else:
        return success ("Password exists")

@app.route('/getPassword/<int:Id>')
def getPassword(Id):

    if not current_user.is_authenticated:
        return failure ("Login required")
    password = Record.query.get_or_404(Id)
    if not password:
        return failure("Password not found")
    return {"status":"success", "Name":password.Name, "Username":password.Username, "Password":password.Password}

"""
@app.route('/clipboard.min.js')
def js():
    return render_template('clipboard.min.js')
"""
@app.route('/add', methods=['POST'])
def add():
    if not current_user.is_authenticated:
        return failure ("Login required")
    data = request.json
    name = data.get('Name')
    username = func.lower(data.get('Username'))
    if not verify_email(data.get('Username')):
        return failure ("Invalid username, example username: username@example.com")
    password = data.get("Password")
    if data.get('Username') == None or password == None:
        return failure ("Username and password can't be empty")
    if Record.query.filter_by(Username = username).first():
        return failure ("This username already exists")
    Owner_Id = current_user.get_id()
    new_record = Record(Name=name, Username=username, Password=password, Owner_Id=Owner_Id, AccountType = 'Personal')
    try:
        db.session.add(new_record)
        db.session.commit()
        password_id = Record.query.filter_by(Username = username).first().Id
        return success (str(password_id))
    except:
        return failure ('There was an issue adding the new password')

@app.route('/', methods=['POST'])
def signin_post():
    if current_user.is_authenticated:
        return failure ("Already logged in")
    data = request.json
    username = func.lower(data.get('Username'))
    password = data.get('Password')
    user = User.query.filter_by(Username = username).first()
    #try:
    if not user or not check_password_hash(user.Master_Password, password):
        return failure('Invalid username or password')
    login_user(user)
    if user.Name:
        session['current_username']='Welcome '+user.Name+'!'
    else:
        session['current_username']='Welcome '+user.Username+'!'

    return success ("Logged in successfully")
    """ 
    except AttributeError:
        flash('Invalid username or password', 'Error!')
        return redirect(url_for('login'))
    """
"""
@app.route('/')
def login():
    return render_template('signin.html')
"""
@app.route('/about')
def about():
    return 'Developed by Egirna Technologies'

"""
@app.route('/details/<int:Id>')
@login_required
def details(Id):
    record_to_update = Record.query.get_or_404(Id)
    return render_template('details.html', record = record_to_update)
"""

@app.route('/random')
def randomGen():
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz!@#$%^&*()*/-+.1234567890{}]['
    password = ''
    for c in range(16):
        password += random.choice(chars)
    return success(password)

@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
        return success ("Logged out successfully")
    else:
        return failure ("Login required")

@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
    try:
        username = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        user = User.query.filter_by(Username=username).first_or_404()
        if user.Confirmed:
            flash('Account already confirmed. Please login.', 'success')
        else:
            user.Confirmed = True
            db.session.add(user)
            db.session.commit()
            flash('You have confirmed your account. Thanks!', 'success')
        return redirect(url_for('index'))

if __name__ == "__main__":
    app.run (port = 8000,debug = True)
