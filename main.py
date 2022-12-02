### DONE!!!

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///users.db")  ###'postgres://USER:PASSWORD@INTERNAL_HOST:PORT/DATABASE'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(1000), nullable=False)
#Line below only required once, when creating DB. 
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=False)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if User.query.filter_by(email=request.form.get('email')).first():
            error = "This email is already registered"
            return render_template("register.html", error=error)
        else:
            new_user = User(
                email = request.form.get('email'),
                #hash password with salt length of 8
                password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=8),
                name = request.form.get('name')
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('secrets'))


    return render_template("register.html", logged_in=current_user.is_authenticated)

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form.get('email')).first()
        if not user:
            error = "That email does not exist. Please try again"
            return render_template("login.html", error=error)
        else:
            if check_password_hash(user.password, request.form.get('password')):
                login_user(user)
                flash('Logged in successfully.')
                print(user.password)
                print(current_user.password)
                return redirect(url_for('secrets'))
            else:
                error = "Invalid password"
                return render_template("login.html", error=error)

    return render_template("login.html", logged_in=current_user.is_authenticated)

@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", logged_in=True, name=current_user.name)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/download')
@login_required
def download():
    return send_from_directory('static', filename="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
