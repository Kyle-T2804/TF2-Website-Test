from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# User model: stores info about each person who signs up.
class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)  # User's ID number
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)  # User's email (must be different for each user)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)  # User's name
    password_hash = db.Column(db.String(255), nullable=False)  # User's password (saved safely)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # When the user account was created
    last_login = db.Column(db.DateTime)  # Last time the user logged in
    is_active = db.Column(db.Boolean, default=True, nullable=False)  # Is the user active?
    email_verified = db.Column(db.Boolean, default=False, nullable=False)  # Is the user's email verified?
    notes = db.relationship('Note')  # All notes this user has made
    gallery_images = db.relationship('GalleryImage')  # All images this user has uploaded

    def set_password(self, password):
        # Saves the password in a safe way
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # Checks if the password is correct
        return check_password_hash(self.password_hash, password)

# Note model: stores each note a user writes.
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Note's ID number
    data = db.Column(db.String(10000))  # What the note says
    date = db.Column(db.DateTime(timezone=True), default=func.now())  # When the note was made
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Which user made the note

# GalleryImage model: stores images uploaded by users.
class GalleryImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Image's ID number
    filename = db.Column(db.String(150), nullable=False)  # Name of the file
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Which user uploaded the image
    upload_time = db.Column(db.DateTime, default=db.func.current_timestamp())  # When the image was uploaded
    description = db.Column(db.String(250))  # Description of the image
    uploader = db.relationship('User')  # The user who uploaded the image