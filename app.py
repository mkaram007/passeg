from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask (__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///records.db'
db = SQLAlchemy(app)

class Record(db.Model):
    Id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(200), nullable= True)
    Username = db.Column(db.String(500), nullable= False)
    Password = db.Column(db.String(500), nullable= False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return "Password created"

@app.route('/', methods=['POST','GET'])
def index():
    if request.method == 'POST':

        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        new_record = Record(Name=name, Username=username, Password=password)
        try:
            db.session.add(new_record)
            db.session.commit()
            return redirect('/')
        except:
            return 'There was an issue adding the new password'
    else:
        records = Record.query.order_by(Record.date_created).all()
        return render_template('index.html', records=records)

@app.route('/delete/<int:Id>')
def delete(Id):
    password_to_delete = Record.query.get_or_404(Id)
    try:
        db.session.delete(password_to_delete)
        db.session.commit()
        return redirect('/')
    except:
        return 'There was a problem deleting this password'

@app.route('/add')
def add():
    return render_template('add.html')

if __name__ == "__main__":
    app.run (port = 8000,debug = True)
