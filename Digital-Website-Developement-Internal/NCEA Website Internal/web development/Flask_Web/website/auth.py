from flask import Blueprint, render_template, url_for, request, flash, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from .models import User, Note
from . import db

auth = Blueprint('auth', __name__)

# sign up route: lets a new user create an account
@auth.route("/sign-up", methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')  # user's email
        username = request.form.get('username')  # user's chosen name
        password1 = request.form.get('password1')  # first password entry
        password2 = request.form.get('password2')  # second password entry (for checking)

        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        # Check if email is long enough
        elif len(email) < 4:
            flash('Email is not valid', category='error')
        # Check if username is long enough
        elif len(username) < 2:
            flash('Username must be at least 2 characters.', category='error')
        # Check if passwords match
        elif password1 != password2:
            flash('Passwords do not match.', category='error')
        # Check if password is strong enough
        elif len(password1) < 8:
            flash('Password must have at least 8 characters.', category='error')
        else:
            # Create new user with hashed password
            new_user = User(
                email=email,
                username=username,
                password=generate_password_hash(password1, method='scrypt:32768:8:1')
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)  # log the user in
            flash('Account Created', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)

# login route: lets a user log in to their account
@auth.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')  # user's email
        password = request.form.get('password')  # user's password
        user = User.query.filter_by(email=email).first()  # find user by email
        if user:
            # Check if password is correct
            if check_password_hash(user.password, password):
                flash('You have logged in successfully', category='success')
                login_user(user, remember=True)  # log the user in
                return redirect(url_for('views.home', user=current_user))
            else:
                flash('Incorrect password.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template('login.html', user=current_user)

# logout route: logs the user out
@auth.route("/logout")
@login_required
def logout():
    logout_user()  # log the user out
    return redirect(url_for('views.home'))



