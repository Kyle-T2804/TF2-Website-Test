from . import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re

# Many-to-many for Note <-> Tag
note_tag = db.Table(
    'note_tag',
    db.Column('note_id', db.Integer, db.ForeignKey('note.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True),
)

thread_tags = db.Table(
    "thread_tags",
    db.Column("thread_id", db.Integer, db.ForeignKey("thread.id", ondelete="CASCADE"), primary_key=True),
    db.Column("tag_id", db.Integer, db.ForeignKey("tag.id", ondelete="CASCADE"), primary_key=True),
)

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)

    # Roles / titles
    role = db.Column(db.String(20), nullable=False, default='member')  # owner|admin|moderator|member
    title = db.Column(db.String(60))  # optional custom title

    # Relationships
    notes = db.relationship('Note', back_populates='author', cascade='all, delete-orphan', lazy=True)
    gallery_images = db.relationship('GalleryImage', back_populates='uploader', cascade='all, delete-orphan', lazy=True)
    threads = db.relationship("Thread", back_populates="author", cascade="all, delete-orphan")
    thread_comments = db.relationship('ThreadComment', back_populates='author', cascade='all, delete-orphan', lazy=True)

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)

    @property
    def is_owner(self) -> bool:
        return self.role == 'owner'

    def can_moderate(self) -> bool:
        return self.role in ('owner', 'admin', 'moderator')

    def can_delete_note(self, note: 'Note') -> bool:
        return self.is_owner or (self.can_moderate() and note.user_id != self.id) or (note.user_id == self.id)

    @property
    def display_title(self) -> str:
        defaults = {'owner': 'Owner', 'admin': 'Admin', 'moderator': 'Moderator', 'member': 'Member'}
        return self.title or defaults.get(self.role, 'Member')

class Note(db.Model):
    __tablename__ = 'note'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    pinned = db.Column(db.Boolean, default=False, nullable=False)

    author = db.relationship('User', back_populates='notes')
    tags = db.relationship('Tag', secondary=note_tag, lazy='subquery',
                           backref=db.backref('notes', lazy=True))

class Tag(db.Model):
    __tablename__ = 'tag'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True, nullable=False)
    slug = db.Column(db.String(40), unique=True, nullable=False, index=True)

    @staticmethod
    def slugify(name: str) -> str:
        s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        return s or "tag"

    def __repr__(self): return f"<Tag {self.name}>"

class GalleryImage(db.Model):
    __tablename__ = 'gallery_image'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(250))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploader = db.relationship('User', back_populates='gallery_images')


# Thread model for contact page topics
class Thread(db.Model):
    __tablename__ = 'thread'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    pinned = db.Column(db.Boolean, default=False)
    locked = db.Column(db.Boolean, default=False)

    author = db.relationship("User", back_populates="threads")
    tags = db.relationship("Tag", secondary=thread_tags, lazy="joined", backref=db.backref("threads", lazy="dynamic"))


# Comment model for replies under a thread
class ThreadComment(db.Model):
    __tablename__ = 'thread_comment'
    id = db.Column(db.Integer, primary_key=True)
    thread_id = db.Column(db.Integer, db.ForeignKey("thread.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    author = db.relationship("User")
    thread = db.relationship("Thread", backref=db.backref("comments", lazy="joined", cascade="all, delete-orphan"))