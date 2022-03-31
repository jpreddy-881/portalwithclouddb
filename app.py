from flask import Flask, render_template, redirect, url_for, send_file, request, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
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
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
import shutil
import os
 
global name

app = Flask(__name__)
app.config["SECRET_KEY"] = "Thisissupposedtobesecret!"
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "mysql+pymysql://jpreddy@jpr123:%s@jpr123.mysql.database.azure.com/avistos" % quote('Prakash@881')

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


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            # if user.password == form.password.data:
            #     return redirect(url_for('dashboard'))

            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for("dashboard"))

        return "<h1>Invalid username or password</h1>"

    return render_template("login.html", form=form)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method="sha256")
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data,
            client=form.client.data,
            password=hashed_password,
        )
        db.session.add(new_user)
        db.session.commit()

        return "<h1>New user has been created!</h1>"

    return render_template("signup.html", form=form)


@app.route("/dashboard")
@login_required
def dashboard():
    name=current_user.username
    return render_template("dashboard.html", name=current_user.username)

@app.route("/logout")
@login_required
def logout():   
    zcwd5 = os.getcwd()  
    zuser_dir9 = os.path.join(zcwd5,current_user.username)
    shutil.rmtree(zuser_dir9)

    logout_user()
    return redirect(url_for("index1"))


admin = Admin(app)
admin.add_view(ModelView(User, db.session))

#######################Tool Started ##############################

@app.route("/tool", methods=["GET", "POST"])
def index():
    
    if request.method == "POST":
        if "file" not in request.files:
            flash("No files selected")
            return redirect("/tool")
        try:
            pass   
           
        except:
            pass
        os.mkdir(current_user.username)
        files = request.files.getlist("file")
        for f in files:
            f.save(os.path.join(current_user.username, f.filename))
        cwd = os.getcwd()
        user_dir1 = os.path.join(cwd,current_user.username)
        global user_dir
        user_dir = os.path.basename(user_dir1)
        app.config["IMAGES"] = user_dir
        for (dirpath, dirnames, filenames) in os.walk(app.config["IMAGES"]):
    
            files = filenames
            break
        app.config["FILES"] = files
        app.config["HEAD"] = 0
        return redirect("/tagger", code=302)
    else:
        return render_template("index.html",myname = current_user.username)

@app.route("/tagger")
def tagger():
    if app.config["HEAD"] == len(app.config["FILES"]):
        return redirect(url_for("final"))
    
    directory = app.config["IMAGES"]
    image = app.config["FILES"][app.config["HEAD"]]
    labels = app.config["LABELS"]
    not_end = not (app.config["HEAD"] == len(app.config["FILES"]) - 1)
    print(not_end)
    return render_template(
        "tagger.html",
        not_end=not_end,
        directory=directory,
        image=image,
        labels=labels,
        head=app.config["HEAD"] + 1,
        len=len(app.config["FILES"]),
    )


@app.route("/next")
def next():
    image = app.config["FILES"][app.config["HEAD"]]
    app.config["HEAD"] = app.config["HEAD"] + 1
    with open(app.config["OUT"], "a") as f:
        for label in app.config["LABELS"]:
            f.write(
                image
                + ","
                + label["id"]
                + ","
                + label["name"]
                + ","
                + str(round(float(label["xMin"])))
                + ","
                + str(round(float(label["xMax"])))
                + ","
                + str(round(float(label["yMin"])))
                + ","
                + str(round(float(label["yMax"])))
                + "\n"
            )
    app.config["LABELS"] = []
    return redirect(url_for("tagger"))


@app.route("/prev")
def prev():
    image = app.config["FILES"][app.config["HEAD"]]
    app.config["HEAD"] = app.config["HEAD"] - 1
    with open(app.config["OUT"], "a") as f:
        for label in app.config["LABELS"]:
            f.write(
                image
                + ","
                + label["id"]
                + ","
                + label["name"]
                + ","
                + str(round(float(label["xMin"])))
                + ","
                + str(round(float(label["xMax"])))
                + ","
                + str(round(float(label["yMin"])))
                + ","
                + str(round(float(label["yMax"])))
                + "\n"
            )
    app.config["LABELS"] = []
    return redirect(url_for("tagger"))


@app.route("/final")
def final():
    return render_template("final.html")


@app.route("/add/<id>")
def add(id):
    xMin = request.args.get("xMin")
    xMax = request.args.get("xMax")
    yMin = request.args.get("yMin")
    yMax = request.args.get("yMax")
    app.config["LABELS"].append(
        {"id": id, "name": "", "xMin": xMin, "xMax": xMax, "yMin": yMin, "yMax": yMax}
    )
    return redirect(url_for("tagger"))


@app.route("/remove/<id>")
def remove(id):
    index = int(id) - 1
    del app.config["LABELS"][index]
    for label in app.config["LABELS"][index:]:
        label["id"] = str(int(label["id"]) - 1)
    return redirect(url_for("tagger"))


@app.route("/label/<id>")
def label(id):
    name = request.args.get("name")
    app.config["LABELS"][int(id) - 1]["name"] = name
    return redirect(url_for("tagger"))


@app.route("/image/<f>")
def images(f):
    images = app.config["IMAGES"]
    return send_file(images + "/" + f)


@app.route("/download")
def download():
    zcwd = os.getcwd()
    zuser_dir1 = os.path.join(zcwd,current_user.username)
    zuser_dir2 = os.path.join(zuser_dir1, "annotations.csv")
    shutil.copyfile("out.csv", zuser_dir2)
    shutil.make_archive("final", "zip", zuser_dir1)
    return send_file(
        "final.zip",
        mimetype="text/csv",
        attachment_filename="final.zip",
        as_attachment=True,
    )

@app.route('/repo')
def repo():
    pass
    return redirect(url_for("index1"))


if __name__ == "__main__":
    app.config["LABELS"] = []
    app.config["HEAD"] = 0
    app.config["OUT"] = "out.csv"
    with open("out.csv", "w") as f:
        f.write("image,id,name,xMin,xMax,yMin,yMax\n")
    # app.run(debug="True")
    app.run(debug="True", host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
