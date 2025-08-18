from flask import Blueprint, render_template, url_for, request, flash, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from .models import User
from . import db
import re

auth = Blueprint('auth', __name__)

def valid_password(pw: str) -> bool:
    return len(pw) >= 6  # Only require 6 or more characters

@auth.route("/sign-up", methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        username = (request.form.get('username') or '').strip()
        password1 = request.form.get('password1') or ''
        password2 = request.form.get('password2') or ''

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', category='error')
        elif User.query.filter_by(username=username).first():
            flash('Username already exists.', category='error')
        elif len(email) < 4 or '@' not in email:
            flash('Email is not valid.', category='error')
        elif len(username) < 2:
            flash('Username must be at least 2 characters.', category='error')
        elif password1 != password2:
            flash('Passwords do not match.', category='error')
        elif not valid_password(password1):
            flash('Password must be at least 6 characters.', category='error')
        else:
            new_user = User(
                email=email,
                username=username,
            )
            new_user.password_hash = generate_password_hash(password1)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)

@auth.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = (request.form.get('identifier') or '').strip()
        password = request.form.get('password1') or ''
        user = User.query.filter((User.email == identifier) | (User.username == identifier)).first()
        if user and hasattr(user, 'password_hash') and check_password_hash(user.password_hash, password):
            login_user(user, remember=True)
            flash('You have logged in successfully', category='success')
            return redirect(url_for('views.home'))
        else:
            flash('Invalid username/email or password.', category='error')
    return render_template('login.html', user=current_user)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('views.home'))



