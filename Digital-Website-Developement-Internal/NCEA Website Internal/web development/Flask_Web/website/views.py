from flask import Blueprint, render_template, url_for, request, flash, redirect, jsonify, current_app
from flask_login import login_user, login_required, logout_user, current_user
from .models import User, Note, GalleryImage
from . import db
import json
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import pytz
from werkzeug.security import generate_password_hash
import re

# Set up the Blueprint for views
views = Blueprint("views", __name__)

# Allowed file extensions for gallery uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Maximum file size for uploads (5 MB)
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

# Local timezone for displaying times (NZST)
local_tz = pytz.timezone('Pacific/Auckland')

def allowed_file(filename):
    """
    Check if the uploaded file has an allowed extension.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def valid_password(pw: str) -> bool:
    """
    Validate the strength of the password.
    Password must be at least 6 characters.
    """
    return len(pw) >= 6  # Only require 6 or more characters

# Home page route
@views.route("/")
@views.route("/home")
@views.route("/index")
def home():
    # Render the home page template
    return render_template("home.html", user=current_user)

# Contact page route
@views.route("/contact", methods=['POST', 'GET'])
@login_required
def contact():
    """
    Handles displaying and posting comments on the contact page.
    Uses POST-Redirect-GET to prevent duplicate submissions on refresh.
    """
    if request.method == 'POST':
        note = request.form.get('note')
        if len(note) < 1:
            flash('Comment field cannot be empty!')
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Comment Added!', category='success')
        # Redirect to prevent duplicate submissions on refresh
        return redirect(url_for('views.contact'))
    return render_template("contact.html", user=current_user)

# Delete note route (AJAX)
@views.route("/delete-note", methods=['POST'])
@login_required
def delete_note():
    """
    Deletes a note/comment via AJAX.
    Only allows deletion if the current user owns the note.
    """
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note and note.user_id == current_user.id:
        db.session.delete(note)
        db.session.commit()
    return jsonify({})

# Individual class page routes
@views.route('/scout')
def scout():
    return render_template('scout.html', user=current_user)

@views.route('/soldier')
def soldier():
    return render_template('soldier.html', user=current_user)

@views.route('/pyro')
def pyro():
    return render_template('pyro.html', user=current_user)

@views.route('/demoman')
def demoman():
    return render_template('demoman.html', user=current_user)

@views.route('/heavy')
def heavy():
    return render_template('heavy.html', user=current_user)

@views.route('/engineer')
def engineer():
    return render_template('engineer.html', user=current_user)

@views.route('/medic')
def medic():
    return render_template('medic.html', user=current_user)

@views.route('/sniper')
def sniper():
    return render_template('sniper.html', user=current_user)

@views.route('/spy')
def spy():
    return render_template('spy.html', user=current_user)

# Gallery route for uploading and displaying images
@views.route('/gallery', methods=['GET', 'POST'])
@login_required
def gallery():
    GALLERY_FOLDER = os.path.join(current_app.root_path, 'static', 'gallery')
    # Ensure the gallery folder exists
    if not os.path.exists(GALLERY_FOLDER):
        os.makedirs(GALLERY_FOLDER)

    if request.method == 'POST':
        file = request.files.get('image')
        description = request.form.get('description')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(GALLERY_FOLDER, filename))
            # Set upload_time as UTC and timezone-aware
            utc_now = datetime.now(pytz.utc)
            new_image = GalleryImage(
                filename=filename,
                uploader_id=current_user.id,
                description=description,
                upload_time=utc_now
            )
            db.session.add(new_image)
            db.session.commit()
            flash('Image uploaded!', 'success')
            return redirect(url_for('views.gallery'))
    images = GalleryImage.query.order_by(GalleryImage.upload_time.desc()).all()
    nz_tz = pytz.timezone('Pacific/Auckland')
    for img in images:
        # Ensure upload_time is timezone-aware before converting
        if img.upload_time.tzinfo is None:
            img.upload_time = pytz.utc.localize(img.upload_time)
        # Format for readability: e.g. "Tue, 13 Aug 2025, 03:45 PM"
        img.nzst = img.upload_time.astimezone(nz_tz).strftime('%a, %d %b %Y, %I:%M %p')
    return render_template('gallery.html', images=images, user=current_user)

# Login route
@views.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login by email or username.
    Uses Flask-Login to manage session.
    """
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password1')
        # Find user by email or username
        user = User.query.filter((User.email == identifier) | (User.username == identifier)).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', category='success')
            return redirect(url_for('views.home'))
        else:
            flash('Invalid email or password.', category='error')
    return render_template('login.html', user=current_user)

# Sign-up route
@views.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    """
    Handles user registration.
    - Checks for existing email
    - Ensures passwords match and meet length requirements
    - Stores password securely using set_password
    - Automatically logs in the user after successful registration
    """
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        username = (request.form.get('username') or '').strip()
        password1 = request.form.get('password1') or ''
        password2 = request.form.get('password2') or ''
        accept_terms = request.form.get('accept_terms') == '1'

        # Basic validation
        if not accept_terms:
            flash('You must accept the Terms of Service.', category='error')
            return redirect(url_for('views.sign_up'))

        if password1 != password2:
            flash('Passwords do not match.', category='error')
            return redirect(url_for('views.sign_up'))

        if not valid_password(password1):
            flash('Password too weak. Include upper/lower, number, and symbol (min 8).', category='error')
            return redirect(url_for('views.sign_up'))

        # Uniqueness
        if User.query.filter_by(email=email).first():
            flash('Email is already in use.', category='error')
            return redirect(url_for('views.sign_up'))
        if User.query.filter_by(username=username).first():
            flash('Username is already taken.', category='error')
            return redirect(url_for('views.sign_up'))

        # Hash and create
        pwd_hash = generate_password_hash(password1, method='pbkdf2:sha256', salt_length=16)
        user = User(email=email, username=username, password_hash=pwd_hash)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash('Account created! Welcome.', category='success')
        return redirect(url_for('views.home'))

    return render_template('sign_up.html', user=current_user)

# About page route
@views.route('/about')
def about():
    # Render the about page template
    return render_template('about_page.html', user=current_user)
