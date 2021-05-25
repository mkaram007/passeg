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
@login_manager.unauthorized_handler
def unauthorized():
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
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    date_modified = db.Column(db.DateTime, default=datetime.utcnow)

class Record(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Owner_Id = db.Column(db.PickleType, nullable=False)
    AccountType = db.Column(db.String(10), nullable=False)
    Name = db.Column(db.String(200), nullable= True)
    Username = db.Column(db.String(500), nullable= False)
    Password = db.Column(db.String(500), nullable= False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    date_modified = db.Column(db.DateTime, default=datetime.utcnow)
    shared_with = db.Column(db.PickleType, nullable= False)

class Group(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), default="New Group")
    members = db.Column(db.PickleType)
    shared_passwords = db.Column(db.PickleType)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    date_modified = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/createGroup', methods=['POST'])
@login_required
def createGroup():
    data = request.json
    if data:
        name = data.get('Name')
    members = [int(current_user.get_id())]
    shared_passwords = []
    try:
        newGroup = Group(name = name, members = members, shared_passwords = shared_passwords)
    except UnboundLocalError:
        newGroup = Group(members = members, shared_passwords = shared_passwords)
    #try:
    db.session.add(newGroup)
    db.session.commit()
    group = Group.query.order_by(Group.date_created.desc()).limit(1)[0]
    return success ("Group created with id: "+str(group.id))
    #except:
    #    return failure ("An issue happened")


@app.route('/revokeShare/<int:passwordId>/<int:userId>', methods=['POST'])
@login_required
def revokeShare(passwordId, userId):
    user = User.query.get(userId)
    if not user:
        return failure("User doesn't exist")
    record = Record.query.get(passwordId)
    if not record:
        return failure("Record doesn't exists")
    if int(current_user.get_id()) not in record.Owner_Id:
        return failure("You're not allowed to share this password")
    shared_with = list(record.shared_with)
    if userId not in shared_with:
        return failure ("This password is already not shared with this user")
    shared_with.remove(userId)
    record.shared_with = shared_with
    try:
        db.session.commit()
        return success (record.shared_with)
    except:
        return failure("An error occured")


@app.route('/revokeOwner/<int:passwordId>/<int:userId>', methods=['POST'])
@login_required
def revokeOwner(passwordId, userId):
    user = User.query.get(userId)
    if not user:
        return failure("User doesn't exist")
    record = Record.query.get(passwordId)
    if not record:
        return failure("Record doesn't exists")
    if int(current_user.get_id()) not in record.Owner_Id:
        return failure("You're not allowed to make a user owner of this password")
    owners = list(record.Owner_Id)
    try:
        owners.remove(userId)
        if len(owners) == 0:
            return failure("You are the only owner of this password")
    except ValueError:
        return failure('This user is already not an owner of this password')
    record.Owner_Id = owners
    try:
        db.session.commit()
        return success (record.Owner_Id)
    except:
        return failure("An error occured")


@app.route('/makeOwner/<int:passwordId>/<int:userId>', methods=['POST'])
@login_required
def makeOwner(passwordId, userId):
    user = User.query.get(userId)
    if not user:
        return failure("User doesn't exist")
    record = Record.query.get(passwordId)
    if not record:
        return failure("Record doesn't exists")
    if int(current_user.get_id()) not in record.Owner_Id:
        return failure("You're not allowed to make a user owner of this password")
    owners = list(record.Owner_Id)
    if userId in owners:
        return failure ("This user is already an owner of this password")
    owners.append(userId)
    record.Owner_Id = owners
    shared_with = list(record.shared_with)
    shared_with.append(userId)
    record.shared_with = list(set(shared_with))

    try:
        db.session.commit()
        return success (record.Owner_Id)
    except:
        return failure("An error occured")


@app.route('/shareWith/<int:passwordId>/<int:userId>', methods=['POST'])
@login_required
def shareWith(passwordId, userId):
    user = User.query.get(userId)
    if not user:
        return failure("User doesn't exist")
    record = Record.query.get(passwordId)
    if not record:
        return failure("Record doesn't exists")
    if int(current_user.get_id()) not in record.Owner_Id:
        return failure("You're not allowed to share this password")
    shared_with = list(record.shared_with)
    if userId in shared_with:
        return failure ("This password is already shared with this user")
    if userId in list(record.Owner_Id):
        return failure ("You are already an owner of this password")
    shared_with.append(userId)
    record.shared_with = shared_with
    try:
        db.session.commit()
        return success (record.shared_with)
    except:
        return failure("An error occured")

    

@app.route('/getCurrentUser')
@login_required
def getCurrentUser():
    return success(current_user.get_id())

@app.route('/editUser/<string:username>', methods = ['POST'])
def editUser(username):
    data = request.json
    newName = data.get('Name')
    newUsername = data.get('Username')
    password = data.get('Password')

    userToEdit = User.query.filter_by(Username = username).first()
    if not userToEdit:
        return failure ("This user doesn't exist")
    if check_password_hash(userToEdit.Master_Password, password):
        if newUsername:
            userToEdit.Username = newUsername
        userToEdit.Name = newName
        try:
            db.session.commit()
            return success("User details modified successfully")
        except exc.IntegrityError:
            return failure ("This username already exists")
    else:
        return failure("Password is incorrect")



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

    newUser = User(Name = name, Username = username, Master_Password = generate_password_hash(password, method='sha256'), Confirmed = False)
    db.session.add(newUser)
    db.session.commit()
    userId = User.query.filter_by(Username = username).first().id
    if current_user.is_authenticated:
        logout_user()

    return success ("Registeration completed with ID: "+ str(userId))
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



@app.route('/delete/<int:Id>', methods=['POST'])
@login_required
def delete(Id):
    password_to_delete = Record.query.get_or_404(Id)
    if int(current_user.get_id()) not in password_to_delete.Owner_Id:
        return failure ("You're not allowed to delete this password")
    try:
        db.session.delete(password_to_delete)
        db.session.commit()
        return success (Id)
    except:
        return failure('There was a problem deleting this password')

@app.route('/getPasswordId/<string:username>')
def getPasswordId(username):
    username = func.lower(username)
    record = Record.query.filter_by(Username = username).first()
    if record:
        return success (record.Id)
    else:
        return failure ("Password not found")

@app.route('/getPasswords')
@login_required
def getPasswords():
    #records = Record.query.filter_by( any(Record.shared_with) = current_user.get_id())
    #records = Record.query.filter(int(current_user.get_id()).in_([1])).all()
    ##records = Record.query.filter(Record.Owner_Id.in_([current_user.get_id(),])).all()
    records = []
    allRecords = Record.query.all()
    currentUser = int(current_user.get_id())
    for record in allRecords:
        if currentUser in record.shared_with or currentUser in record.Owner_Id:
            records.append(record)

    #records = Record.query.filter_by(Record.shared_with.any_(shared_with = current_user.get_id()))
    #records = Record.query.filter(Record.shared_with.has(current_user.get_id()))
    recs = []
    for record in records:
        recs.append(str({"id":record.id, "Name":record.Name, "Username":record.Username, "Password":record.Password, "Owner":record.Owner_Id, "Shared with":record.shared_with}))
    ','.join(recs)
    return success (recs)


@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    record_to_update = Record.query.get_or_404(id)
    currentUser = int(current_user.get_id())
    if currentUser not in record_to_update.Owner_Id or currentUser not in record_to_update.shared_with:
        return failure("You're not allowed to update this password")
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
@login_required
def getPassword(Id):

    password = Record.query.get_or_404(Id)
    if not password:
        return failure("Password not found")
    return {"status":"success", "Name":password.Name, "Username":password.Username, "Password":password.Password, "Shared with":password.shared_with, "Owners":password.Owner_Id}

@app.route('/add', methods=['POST'])
@login_required
def add():
    data = request.json
    name = data.get('Name')
    username = func.lower(data.get('Username'))
    if not verify_email(data.get('Username')):
        return failure ("Invalid username, example username: username@example.com")
    password = data.get("Password")
    if data.get('Username') == None or password == None:
        return failure ("Username and password can't be empty")
    records = Record.query.filter_by(Username = username).all()
    if records:
        for record in records:
            if int(current_user.get_id()) in record.Owner_Id:
                return failure ("This username already exists")
    currentUser = int(current_user.get_id())
    Owner_Id = []
    Owner_Id.append(currentUser)
    shared_with = []
    new_record = Record(Name=name, Username=username, Password=password, Owner_Id=Owner_Id, AccountType = 'Personal', shared_with = shared_with)
#    try:
    db.session.add(new_record)
    db.session.commit()
    passwords = Record.query.filter_by(Username = username).all()
    ids = []
    for password in passwords:
        ids.append(password.id)

    return success (ids)
#    except:
#        return failure ('There was an issue adding the new password')

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

@app.route('/about')
def about():
    return 'Developed by Egirna Technologies'


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
