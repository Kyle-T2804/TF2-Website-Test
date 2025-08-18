from flask import Blueprint, render_template, url_for, request, flash, redirect, jsonify, current_app
from flask_login import login_user, login_required, logout_user, current_user
from .models import User, Note, GalleryImage, Tag
from . import db
from werkzeug.utils import secure_filename
from datetime import datetime
from werkzeug.security import generate_password_hash
import re
import pytz
import os
import json

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

def _seed_default_tags():
    defaults = [
        ('Question', 'question'),
        ('Feedback', 'feedback'),
        ('Bug', 'bug'),
        ('Suggestion', 'suggestion'),
        ('Off-topic', 'off-topic'),
    ]
    if Tag.query.count() == 0:
        for name, slug in defaults:
            db.session.add(Tag(name=name, slug=slug))
        db.session.commit()

# Home page route
@views.route("/")
@views.route("/home")
@views.route("/index")
def home():
    # Render the home page template
    return render_template("home.html", user=current_user)

# Contact page route
@views.route("/contact", methods=['GET'])
def contact():
    _seed_default_tags()
    # Pinned first, then newest
    notes = Note.query.order_by(Note.pinned.desc(), Note.created_at.desc()).all()
    all_tags = Tag.query.order_by(Tag.name.asc()).all()
    return render_template("contact.html", user=current_user, notes=notes, all_tags=all_tags)

# Add note route (AJAX)
@views.route('/add-note', methods=['POST'])
@login_required
def add_note():
    # Accept JSON or form POST
    data = request.get_json(silent=True) or {}
    content = (data.get('content') or request.form.get('content') or request.form.get('note') or '').strip()
    tags_raw = data.get('tags') or request.form.get('tags') or ''
    if isinstance(tags_raw, str):
        tag_slugs = [s.strip() for s in tags_raw.split(',') if s.strip()]
    else:
        tag_slugs = list(tags_raw)  # assume list

    if len(content) < 3:
        msg = 'Comment must be at least 3 characters.'
        if request.is_json:
            return jsonify(success=False, message=msg), 400
        flash(msg, 'error')
        return redirect(url_for('views.contact'))

    # Limit to 3 tags (like Discord forums)
    tag_slugs = tag_slugs[:3]
    selected_tags = Tag.query.filter(Tag.slug.in_(tag_slugs)).all()

    note = Note(content=content, author=current_user)
    note.tags = selected_tags
    db.session.add(note)
    db.session.commit()

    if request.is_json:
        return jsonify(success=True, id=note.id)
    flash('Comment posted.', 'success')
    return redirect(url_for('views.contact'))

# Delete note route (AJAX)
@views.route("/delete-note", methods=['POST'])
@login_required
def delete_note():
    data = request.get_json(silent=True) or {}
    note_id = data.get('noteId') or request.form.get('noteId')
    note = Note.query.get(note_id)
    if not note:
        return jsonify(success=False, message='Not found'), 404
    # Owner can delete any; moderators/admins can delete others; authors can delete their own
    if not current_user.can_delete_note(note):
        return jsonify(success=False, message='Forbidden'), 403
    db.session.delete(note)
    db.session.commit()
    return jsonify(success=True)

# NEW: Pin/Unpin (Owner only)
@views.route('/notes/<int:note_id>/pin', methods=['POST'])
@login_required
def pin_note(note_id):
    if not current_user.is_owner:
        return jsonify(success=False, message='Forbidden'), 403
    data = request.get_json(silent=True) or {}
    desired = bool(data.get('pinned', True))
    note = Note.query.get_or_404(note_id)
    note.pinned = desired
    db.session.commit()
    return jsonify(success=True, pinned=note.pinned)

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
            flash('Password must be at least 6 characters.', category='error')
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
