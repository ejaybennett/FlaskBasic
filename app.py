#from distutils.log import Log
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, url_for, request, redirect, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField
from flask_wtf.file import FileField
from wtforms.validators import DataRequired, Length, ValidationError
from flask_login import LoginManager, login_user, login_required, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
import  os
app = Flask(__name__)
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost:5432/login'

# x 1. Add boiler plate
# x 2. Need a user class with an id variable
# x 3. User loader -> function that takes in a user id 
# # and gives back the user object, or none if none exists with taht id
# 4. Call the login_user function on the user object 
# 5. If you want to restrict a route so only logged in people can see it, you mark the function
# with the @login_required decorator

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10), unique=True)
    password = db.Column(db.String(500))
class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    link = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    def get_username(self):
        return User.query.get(self.user_id).username

db.create_all()

@login_manager.user_loader
def load_user(id):
    return User.query.get(id)

@login_manager.unauthorized_handler
def login_needed():
    return redirect(url_for("login"))

class LoginInfo(FlaskForm):
    username = StringField(name="username", validators=[DataRequired(),Length(3,10)])
    password = StringField(name="password", validators=[DataRequired(),Length(3,10)])

class AddLink(FlaskForm):
    name = StringField(name="name")
    link = StringField(name="link")

@app.route("/")
@login_required
def home():
    links = Link.query.all()
    return render_template("home.html", name = current_user.username, form = AddLink(), links=links)

@app.route("/login", methods = ["GET"])
def login_page():
    return render_template("login.html", form = LoginInfo())

@app.route("/signup", methods = ["GET"])
def signup_page():
    return render_template("signup.html", form = LoginInfo())

@app.route("/login", methods = ["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    result = User.query.filter_by(username=username).first()
    if result == None or not check_password_hash(result.password, password):
        return "Incorrect login info!"
    else:
        login_user(result)
        return redirect(url_for("home"))

@app.route("/signup", methods = ["POST"])
def signup():
    username = request.form["username"]
    password = request.form["password"]
    result = User.query.filter_by(username=username).first()
    if result != None:
        return "Username taken"
    else:
        user = User(username=username, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for("home"))

@app.route("/add_link", methods = ["POST"])
def add_link():
    link = Link(name=request.form["name"], link=request.form["link"], user_id = current_user.id)
    db.session.add(link)
    db.session.commit()
    return redirect(url_for("home"))

@app.route("/delete", methods = ["POST"])
def delete_link():
    Link.query.filter_by(id=int(request.form["link_id"])).delete()
    db.session.commit()
    return redirect(url_for("home"))

@app.route("/edit", methods = ["POST"])
def edit_link():
    link = Link.query.filter_by(id=int(request.form["link_id"])).first()
    if request.form["name"] != "":
        link.name = request.form["name"]
    if request.form["link"] != "":
        link.link = request.form["link"]
    db.session.commit()
    return redirect(url_for("home"))

app.run()