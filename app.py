
from flask import Flask, render_template, redirect, url_for, session, g
from flask_session import Session
from datetime import datetime
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from pyasn1.type.univ import Null
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
import pathlib
import requests
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
import threading
import os
import shutil
from flask import Flask, redirect, url_for, request, flash
from flask import render_template
from flask import send_file
import csv
from urllib.parse import quote 
from flask_migrate import Migrate

app = Flask(__name__)
app.config["SECRET_KEY"] = "Thisissupposedtobesecret!"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://jpr@avistosdb01:%s@avistosdb01.mysql.database.azure.com/avistos" % quote('Prakash.881')

bootstrap = Bootstrap(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    role = db.Column(db.String(100))
    client = db.Column(db.String(100))
  

@login_manager.user_loader
def load_user(user_id):
    normal = str(user_id)
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField(
        "username", validators=[InputRequired(), Length(min=4, max=15)]
    )
    password = PasswordField(
        "password", validators=[InputRequired(), Length(min=8, max=80)]
    )
    role = StringField("role", validators=[InputRequired(), Length(min=4, max=25)])
    client = StringField("client ", validators=[InputRequired(), Length(min=4, max=25)])
    remember = BooleanField("remember me")


class RegisterForm(FlaskForm):
    email = StringField(
        "email",
        validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)],
    )
    username = StringField(
        "username", validators=[InputRequired(), Length(min=4, max=15)]
    )
    password = PasswordField(
        "password", validators=[InputRequired(), Length(min=8, max=80)]
    )
    role = StringField("role", validators=[InputRequired(), Length(min=4, max=25)])
    client = StringField("client ", validators=[InputRequired(), Length(min=4, max=25)])
    remember = BooleanField("remember me")



@app.route("/")
def index1():
    return render_template("index1.html")


@app.route("/login1", methods=["GET", "POST"])
def login1():

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:

            if user.password == (form.password.data):
                login_user(user, remember=form.remember.data)

                return redirect(url_for("dashboard1"))

    return render_template("login1.html", form=form)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        #hashed_password = generate_password_hash(form.password.data, method="sha256")
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data,
            client=form.client.data,
            password=form.password.data
            #hashed_password,
        )
        db.session.add(new_user)
        db.session.commit()

        return "<h1>New user has been created!</h1>"

    return render_template("signup.html", form=form)


@app.route("/dashboard1")
@login_required
def dashboard1():
    return render_template("dashboard1.html", name=current_user.username,  datetime=str(datetime.now()) )


@app.route("/logout")
@login_required
def logout():
    session["user"] = None
    logout_user()
    return redirect(url_for("index1"))


admin = Admin(app)
admin.add_view(ModelView(User, db.session))

########################## Google Flow Started  #######################################

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "919473826120-rp26v9k64c5d7ourmgqj7cmq2b5pfp28.apps.googleusercontent.com"

client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    
    redirect_uri="http://127.0.0.1:5000/callback"
    
)


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    
    gid =  session["google_id"]
    gname =  session["name"]
        
    return redirect("/dashboard")
 


@app.route("/logout1")
def logout1():
    session.clear()
    return redirect("/")
   


@app.route("/")
def index():
    return "Hello World <a href='/login'><button>Login</button></a>"

@app.route("/dashboard")
@login_is_required
def protected_area():
    return render_template("dashboard.html",datetime=str(datetime.now()),name=session["name"] )
        

########################### Endof Google flow #################################

if __name__ == "__main__":
    #app.run(debug=True)
    app.run(debug="True", host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
