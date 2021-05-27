import werkzeug
import os
from flask import Flask, render_template, url_for, request, redirect, flash, Response, session
import json
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
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
import rsa
from Crypto.Cipher import AES
from secrets import token_bytes


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

def encrypt(plainPassword, userKey):
    cipher = AES.new(userKey, AES.MODE_EAX)
    nonce = cipher.nonce
    cipherPassword, tag= cipher.encrypt_and_digest(plainPassword.encode("ascii"))
    return nonce, cipherPassword, tag

def decrypt(nonce, cipherPassword, tag, userKey):
    cipher = AES.new(userKey,  AES.MODE_EAX, nonce=nonce)
    plainPassword = cipher.decrypt(cipherPassword)
    try:

        cipher.verify(tag)
        return plainPassword.decode('ascii')
    except ValueError:
        return False

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(500), nullable= True)
    Username = db.Column(db.String(500), nullable= False, unique=True)
    Master_Password = db.Column(db.String(500), nullable=False)
    Confirmed = db.Column(db.Boolean, nullable=False, default=False)
    UserKey = db.Column(db.String(1000), nullable=False, unique=True)
    PublicKey = db.Column(db.String(1000), nullable=False, unique=True)
    PrivateKey = db.Column(db.String(1000), nullable=False, unique=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    date_modified = db.Column(db.DateTime, default=datetime.utcnow)

class Record(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Owner_Id = db.Column(db.PickleType, nullable=False)
    AccountType = db.Column(db.String(10), nullable=False)
    Name = db.Column(db.String(200), nullable= True)
    Username = db.Column(db.String(500), nullable= False)
    Password = db.Column(db.String(500), nullable= False)
    Nonce = db.Column(db.String(500), nullable = False)
    Tag = db.Column(db.String(500), nullable = False)
    Creator_Id = db.Column(db.Integer, nullable = False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    date_modified = db.Column(db.DateTime, default=datetime.utcnow)
    shared_with = db.Column(db.PickleType, nullable= False)

class Group(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), default="New Group")
    members = db.Column(db.PickleType)
    managers = db.Column(db.PickleType)
    owners = db.Column(db.PickleType)
    shared_passwords = db.Column(db.PickleType)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    date_modified = db.Column(db.DateTime, default=datetime.utcnow)


@app.route('/makeGroupOwner/<int:userId>/<int:groupId>', methods=['POST'])
@login_required
def makeGroupOwner(userId, groupId):
    currentUser = int(current_user.get_id())
    user = User.query.get(userId)
    if not user:
        return failure ("This user doesn't exist")
    group = Group.query.get(groupId)
    if not group:
        return failure ("This group doesn't exist")
    if currentUser not in group.owners:
        return failure ("You are not an owner of this group")
    owners = list(group.owners)
    managers = list(group.managers)
    if userId not in group.members:
        return failure ("This user is not a member in this group")
    if userId in owners:
        return failure ("This user is already an owner in this group")
    managers.append(userId)
    owners.append(userId)
    group.managers = managers
    group.owners = owners
    try:
        db.session.commit()
        return success("This user is now an owner of the group")
    except:
        return failure("An issue happened, contact the developer")

@app.route('/makeGroupManager/<int:userId>/<int:groupId>', methods=['POST'])
@login_required
def makeGroupManager(userId, groupId):
    currentUser = int(current_user.get_id())
    user = User.query.get(userId)
    if not user:
        return failure ("This user doesn't exist")
    group = Group.query.get(groupId)
    if not group:
        return failure ("This group doesn't exist")
    if currentUser not in group.owners:
        return failure ("You are not an owner of this group")
    managers = list(group.managers)
    if userId not in group.members:
        return failure ("This user is not a member in this group")
    if userId in managers:
        return failure ("This user is already a manager in this group")
    managers.append(userId)
    group.managers = managers
    try:
        db.session.commit()
        return success("This user is now a manager of the group")
    except:
        return failure("An issue happened, contact the developer")

@app.route('/addPasswordToGroup/<int:passwordId>/<int:groupId>', methods=['POST'])
@login_required
def addPasswordToGroup(passwordId, groupId):
    group = Group.query.get(groupId)
    currentUser = int(current_user.get_id())
    if not group:
        return failure ("This group doesn't exist")
    password = Record.query.get(passwordId)
    if not password:
        return failure ("This password doesn't exist")
    if currentUser not in group.members:
        return failure ("You are not a member in this group")
    if currentUser not in group.managers:
        return failure ("You are not a manager in this group")
    passwords = list(group.shared_passwords)
    if passwordId in passwords:
        return failure ("This password is already in this group")
    passwords.append(passwordId)
    group.shared_passwords = passwords
    try:
        db.session.commit()
        return success ("Password is added to the group")
    except:
        return failure ("An issue happened")



@app.route('/addUserToGroup/<int:userId>/<int:groupId>', methods=['POST'])
@login_required
def addUserToGroup(userId, groupId):
    currentUser = int(current_user.get_id())
    group = Group.query.get(groupId)
    if not group:
        return failure ("This group doesn't exist")
    user = User.query.get(userId)
    if not user:
        return failure ("This user doesn't exist")
    if currentUser not in group.members:
        return failure ("You are not a member in this group")
    if currentUser not in group.managers:
        return failure ("You are not a manager in this group")
    members = list(group.members)
    if userId in members:
        return failure ("This user is already a member of this group")
    members.append(userId)
    group.members = members
    try:
        db.session.commit()
        return success ("User has been added to the group")
    except:
        return failure ("An issue happened")




@app.route('/createGroup', methods=['POST'])
@login_required
def createGroup():
    data = request.json
    if data:
        name = data.get('Name')
    members = [int(current_user.get_id())]
    managers = [int(current_user.get_id())]
    owners = [int(current_user.get_id())]
    shared_passwords = []
    try:
        newGroup = Group(name = name, members = members, shared_passwords = shared_passwords, managers = managers, owners = owners)
    except UnboundLocalError:
        newGroup = Group(members = members, shared_passwords = shared_passwords, managers = managers, owners = owners)
    try:
        db.session.add(newGroup)
        db.session.commit()
        group = Group.query.order_by(Group.date_created.desc()).limit(1)[0]
        return success ("Group created with id: "+str(group.id))
    except:
        return failure ("An issue happened")


@app.route('/revokePasswordShare/<int:passwordId>/<int:userId>', methods=['POST'])
@login_required
def revokePasswordShare(passwordId, userId):
    user = User.query.get(userId)
    currentUser = int(current_user.get_id())
    if not user:
        return failure("User doesn't exist")
    record = Record.query.get(passwordId)
    if not record:
        return failure("Record doesn't exists")
    if currentUser not in record.Owner_Id:
        return failure("You're not allowed to share this password")
    shared_with = list(record.shared_with)
    if userId == currentUser:
        return failure ("You are an owner of this password")
    if userId not in shared_with:
        return failure ("This password is not even shared with this user")
    shared_with.remove(userId)
    record.shared_with = shared_with
    try:
        db.session.commit()
        return success (record.shared_with)
    except:
        return failure("An error occured")


@app.route('/revokePasswordOwner/<int:passwordId>/<int:userId>', methods=['POST'])
@login_required
def revokePasswordOwner(passwordId, userId):
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


@app.route('/makePasswordOwner/<int:passwordId>/<int:userId>', methods=['POST'])
@login_required
def makePasswordOwner(passwordId, userId):
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


@app.route('/sharePasswordWith/<int:passwordId>/<int:userId>', methods=['POST'])
@login_required
def sharePasswordWith(passwordId, userId):
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
        return failure ("This user is already an owner of this password")
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

@app.route('/updateUser/<username>', methods = ['POST'])
def updateUser(username):
    data = request.json
    newName = data.get('Name')
    newUsername = data.get('Username')
    password = data.get('Password')

    userToEdit = User.query.filter_by(Username = username).first()
    if not userToEdit:
        return failure ("This user doesn't exist")
    if check_password_hash(userToEdit.Master_Password, password):
        if (not newUsername or userToEdit.Username == newUsername)and (not newName or userToEdit.Name == newName):
            return failure ("No changes to apply")
        if newUsername:
            userToEdit.Username = newUsername
        if newName:
            userToEdit.Name = newName
        try:
            db.session.commit()
            return success("User details modified successfully")
        except exc.IntegrityError:
            return failure ("This username already exists")
    else:
        return failure("Password is incorrect")



@app.route('/signup', methods=['POST'])
def signup():
    if current_user.is_authenticated:
        return failure("Logout to register a new user")
    data = request.json
    name = data.get('Name')
    username = data.get('Username').lower()
    #if len(username.split('@')) == 1 or len(username.split('@')[1].split('.')) ==1:
    if not verify_email(username):
        return failure ("Invalid username, example username: username@example.com")
    password = data.get('Password')
    try:
        if len(username) == 0 or len(password) == 0:
            return failure("Inproper username or password")
    except TypeError:
        return failure("Inproper username or password")
    if User.query.filter_by(Username = username).first():
        return failure('This username already exists')

    publicKey, privateKey = rsa.newkeys(512)
    userKey = token_bytes(16)

    newUser = User(Name = name, Username = username, Master_Password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8), Confirmed = False, PublicKey = str(publicKey), PrivateKey = str(privateKey), UserKey = userKey)
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



@app.route('/deletePassword/<int:id>', methods=['POST'])
@login_required
def deletePassword(id):
    password_to_delete = Record.query.get_or_404(id)
    if int(current_user.get_id()) not in password_to_delete.Owner_Id:
        return failure ("You're not allowed to delete this password")
    try:
        db.session.delete(password_to_delete)
        db.session.commit()
        return success (id)
    except:
        return failure('There was a problem deleting this password')

@app.route('/getPasswordId/<username>')
def getPasswordId(username):
    username = username.lower()
    record = Record.query.filter_by(Username = username).first()
    if record:
        return success (record.id)
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
        creatorKey = User.query.get(record.Creator_Id).UserKey
        passwd = decrypt(record.Nonce, record.Password, record.Tag, creatorKey)
        recs.append(str({"id":record.id, "Name":record.Name, "Username":record.Username, "Password":passwd, "Owner":record.Owner_Id, "Shared with":record.shared_with}))
    ','.join(recs)
    return success (recs)


@app.route('/updatePassword/<int:id>', methods=['GET', 'POST'])
@login_required
def updatePassword(id):
    record_to_update = Record.query.get_or_404(id)
    currentUser = int(current_user.get_id())
    if currentUser not in record_to_update.Owner_Id and currentUser not in record_to_update.shared_with:
        return failure("You're not allowed to update this password")
    if request.method == 'POST':
        data = request.json
        name = data.get('Name')
        username = data.get('Username')
        password = data.get('Password')
        if (not name and not username and not password) or (record_to_update.Name == name and record_to_update.Username == username.lower() and record_to_update.Password==password):
            return failure ("No change to apply")
        if name:
            record_to_update.Name = name
        if not verify_email(username):
            return failure ("Invalid username, example username: username@example.com")
        if username:
            record_to_update.Username = username.lower()
        if password:
            record_to_update.Password = password
        record_to_update.date_modified = datetime.utcnow()
        try:
            db.session.commit()
            return success("Password has been updated successfully")
        except:
            return failure ("There was a problem updating this password")
    else:
        return success ("Password exists")

@app.route('/getPassword/<int:id>')
@login_required
def getPassword(id):
    password = Record.query.get_or_404(id)
    if not password:
        return failure("Password not found")
    currentUser = int(current_user.get_id())
    if not currentUser in password.Owner_Id and not currentUser in password.shared_with:
        return failure ("You don't have access to this password")
    creatorKey = User.query.get(password.Creator_Id).UserKey
    passwd = decrypt(password.Nonce, password.Password, password.Tag, creatorKey)
    return {"status":"success", "Name":password.Name, "Username":password.Username, "Password":passwd, "Shared with":password.shared_with, "Owners":password.Owner_Id}

@app.route('/addPassword', methods=['POST'])
@login_required
def addPassword():
    data = request.json
    name = data.get('Name')
    username = data.get('Username').lower()
    if not verify_email(username):
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
    userKey = User.query.get(currentUser).UserKey
    Owner_Id = []
    Owner_Id.append(currentUser)
    shared_with = []
    nonce, cipherPassword, tag = encrypt(password, userKey)
    new_record = Record(Name=name, Username=username, Password=cipherPassword, Owner_Id=Owner_Id, AccountType = 'Personal', shared_with = shared_with, Nonce = nonce, Tag = tag, Creator_Id = currentUser)
    try:
        db.session.add(new_record)
        db.session.commit()
        passwords = Record.query.filter_by(Username = username).all()
        ids = []
        for password in passwords:
            ids.append(password.id)

        return success (ids)
    except:
        return failure ('There was an issue adding the new password')

@app.route('/login', methods=['POST'])
def login():
    if current_user.is_authenticated:
        return failure ("Already logged in: "+current_user.get_id())
    data = request.json
    username = data.get('Username').lower()
    password = data.get('Password')
    user = User.query.filter_by(Username = username).first()
    if not user or not check_password_hash(user.Master_Password, password):
        return failure('Invalid username or password')
    login_user(user)
    return success ("Logged in successfully: "+str(user.id))

@app.route('/generateRandomPassword')
def generateRandomPassword():
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
