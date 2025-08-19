from flask import Blueprint, render_template, request, redirect, url_for, jsonify, abort, flash, current_app
from flask_login import login_required, current_user, login_user
from .models import db, Thread, ThreadComment, Tag, User, Note, GalleryImage, Notification, ThreadReaction  # ensure these exist
from sqlalchemy import func
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

# --- Notifications ---
@views.app_context_processor
def inject_unread_count():
    count = 0
    if current_user.is_authenticated:
        try:
            count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        except Exception:
            count = 0
    return { 'unread_notifications': count }

@views.route('/notifications')
@login_required
def notifications_page():
    items = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(50).all()
    # Simple JSON for now; could render a template later
    def fmt(n):
        return {
            'id': n.id,
            'kind': n.kind,
            'is_read': n.is_read,
            'created_at': n.created_at.isoformat(),
            'thread_id': n.thread_id,
            'comment_id': n.comment_id,
            'actor': getattr(n.actor, 'username', 'unknown'),
        }
    return jsonify([fmt(n) for n in items])

@views.route('/notifications/mark-read', methods=['POST'])
@login_required
def notifications_mark_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({ Notification.is_read: True })
    db.session.commit()
    return jsonify({ 'ok': True })

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

def _safe_slugify(name: str) -> str:
    name = (name or "").strip()
    if hasattr(Tag, 'slugify') and callable(getattr(Tag, 'slugify')):
        return Tag.slugify(name)
    # fallback simple slugify
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "tag"

# --- Users suggestion API for @-mention autocomplete ---
@views.route("/api/users/suggest", methods=["GET"])
@login_required
def api_user_suggest():
    q = (request.args.get("q") or "").strip()
    thread_id_raw = request.args.get("thread_id")
    thread_id = int(thread_id_raw) if thread_id_raw and thread_id_raw.isdigit() else None
    # normalize and validate
    if q.startswith("@"): q = q[1:]
    q = re.sub(r"[^A-Za-z0-9_]+", "", q)[:32]
    if not q:
        return jsonify([])

    q_prefix = f"{q.lower()}%"

    seen = set()
    out = []

    # Prefer participants in thread first
    if thread_id:
        try:
            part_q = (
                User.query
                .join(ThreadComment, ThreadComment.user_id == User.id)
                .filter(ThreadComment.thread_id == thread_id)
                .filter(func.lower(User.username).like(q_prefix))
                .order_by(func.lower(User.username).asc())
                .limit(8)
                .all()
            )
            for u in part_q:
                if u.id in seen: continue
                seen.add(u.id)
                out.append({
                    "id": u.id,
                    "username": u.username,
                    "title": u.display_title,
                    "role": u.role,
                })
                if len(out) >= 8: break
        except Exception:
            pass

    # Then global users if room remains
    if len(out) < 8:
        more_q = (
            User.query
            .filter(func.lower(User.username).like(q_prefix))
            .order_by(func.lower(User.username).asc())
            .limit(8)
            .all()
        )
        for u in more_q:
            if u.id in seen: continue
            seen.add(u.id)
            out.append({
                "id": u.id,
                "username": u.username,
                "title": u.display_title,
                "role": u.role,
            })
            if len(out) >= 8: break

    return jsonify(out)

# Home page route
@views.route("/")
@views.route("/home")
@views.route("/index")
def home():
    # Render the home page template
    return render_template("home.html", user=current_user)

# Contact page route

# Contact page: list threads
@views.route("/contact", methods=['GET'])
def contact():
    # ensure some default tags exist for first-run UX
    try:
        _seed_default_tags()
    except Exception:
        pass
    threads = Thread.query.order_by(Thread.pinned.desc(), Thread.created_at.desc()).all()
    # Preload reaction counts per thread
    reaction_counts = {}
    try:
        rows = (
            db.session.query(ThreadReaction.thread_id, ThreadReaction.emoji, func.count(ThreadReaction.id))
            .group_by(ThreadReaction.thread_id, ThreadReaction.emoji)
            .all()
        )
        for tid, emoji, cnt in rows:
            reaction_counts.setdefault(tid, {})[emoji] = cnt
    except Exception:
        pass
    # Map current user's own reactions for quick UI state
    my_reacts = set()
    if current_user.is_authenticated:
        try:
            mine = ThreadReaction.query.filter_by(user_id=current_user.id).all()
            for r in mine:
                my_reacts.add((r.thread_id, r.emoji))
        except Exception:
            pass
    return render_template("contact.html", user=current_user, threads=threads, reaction_counts=reaction_counts, my_reacts=my_reacts)

@views.route("/threads/<int:thread_id>/reactions", methods=["GET"])
def get_thread_reactions(thread_id: int):
    # Return counts and whether current user reacted
    thr = Thread.query.get_or_404(thread_id)
    rows = (
        db.session.query(ThreadReaction.emoji, func.count(ThreadReaction.id))
        .filter(ThreadReaction.thread_id == thread_id)
        .group_by(ThreadReaction.emoji)
        .all()
    )
    counts = {e: c for e, c in rows}
    mine = []
    if current_user.is_authenticated:
        mine = [r.emoji for r in ThreadReaction.query.filter_by(thread_id=thread_id, user_id=current_user.id).all()]
    return jsonify({"counts": counts, "mine": mine})

@views.route("/threads/<int:thread_id>/react", methods=["POST"])
@login_required
def toggle_thread_reaction(thread_id: int):
    data = request.get_json(silent=True) or {}
    emoji = (data.get("emoji") or "").strip()
    if not emoji:
        return jsonify({"error": "emoji required"}), 400
    thr = Thread.query.get_or_404(thread_id)
    # Constrain to a small number of graphemes (1 ideally). We'll cap to 16 chars to be safe.
    emoji = emoji[:32]
    existing = ThreadReaction.query.filter_by(thread_id=thread_id, user_id=current_user.id, emoji=emoji).first()
    if existing:
        db.session.delete(existing)
        action = "removed"
    else:
        db.session.add(ThreadReaction(thread_id=thread_id, user_id=current_user.id, emoji=emoji))
        action = "added"
    db.session.commit()
    # return updated counts
    rows = (
        db.session.query(ThreadReaction.emoji, func.count(ThreadReaction.id))
        .filter(ThreadReaction.thread_id == thread_id)
        .group_by(ThreadReaction.emoji)
        .all()
    )
    counts = {e: c for e, c in rows}
    return jsonify({"ok": True, "action": action, "counts": counts})
# Pin/unpin a thread (owner/admin/moderator)
@views.route("/contact/thread/<int:thread_id>/pin", methods=['POST'])
@login_required
def pin_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    if not current_user.can_moderate():
        flash('You do not have permission.', 'error')
        return redirect(url_for('views.view_thread', thread_id=thread.id))
    thread.pinned = not thread.pinned
    db.session.commit()
    flash(('Pinned' if thread.pinned else 'Unpinned') + ' thread.', 'success')
    return redirect(url_for('views.view_thread', thread_id=thread.id))

# Lock/unlock a thread (owner/admin/moderator)
@views.route("/contact/thread/<int:thread_id>/lock", methods=['POST'])
@login_required
def lock_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    if not current_user.can_moderate():
        flash('You do not have permission.', 'error')
        return redirect(url_for('views.view_thread', thread_id=thread.id))
    thread.locked = not thread.locked
    db.session.commit()
    flash(('Locked' if thread.locked else 'Unlocked') + ' thread.', 'success')
    return redirect(url_for('views.view_thread', thread_id=thread.id))

# Delete a thread (owner/admin/moderator)
@views.route("/contact/thread/<int:thread_id>/delete", methods=['POST'])
@login_required
def delete_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    if not current_user.can_moderate() and thread.user_id != current_user.id:
        flash('You do not have permission.', 'error')
        return redirect(url_for('views.contact'))
    db.session.delete(thread)
    db.session.commit()
    flash('Thread deleted.', 'success')
    return redirect(url_for('views.contact'))

# --- Tag APIs ---
@views.route("/api/tags")
def api_tags():
    tags = Tag.query.order_by(Tag.name.asc()).all()
    return jsonify([{"id": t.id, "name": t.name, "slug": t.slug} for t in tags])

def _require_tag_manager():
    if not current_user.is_authenticated or current_user.role not in ("owner","admin"):
        abort(403)

@views.route("/admin/tags", methods=["POST"])
@login_required
def admin_create_tag():
    _require_tag_manager()
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error":"name required"}), 400
    slug = _safe_slugify(name)
    # prevent dup
    if Tag.query.filter(func.lower(Tag.slug)==slug.lower()).first():
        return jsonify({"error":"exists"}), 409
    tag = Tag(name=name, slug=slug)
    db.session.add(tag)
    db.session.commit()
    return jsonify({"ok": True, "id": tag.id})

@views.route("/admin/tags/<int:tag_id>", methods=["DELETE"])
@login_required
def admin_delete_tag(tag_id: int):
    _require_tag_manager()
    tag = Tag.query.get_or_404(tag_id)
    db.session.delete(tag)
    db.session.commit()
    return jsonify({"ok": True})

# --- Thread create with description + tags ---
@views.route("/threads/create", methods=["POST"])
@login_required
def create_thread():
    title = (request.form.get("title") or "").strip()
    desc = (request.form.get("description") or "").strip()
    tag_ids_csv = (request.form.get("tag_ids") or "").strip()
    if not title or not desc:
        flash("Title and description are required.", "error")
        return redirect(url_for("views.contact"))

    thread = Thread(title=title, user_id=current_user.id)
    # attach tags
    if tag_ids_csv:
        ids = [int(x) for x in tag_ids_csv.split(",") if x.isdigit()]
        if ids:
            tags = Tag.query.filter(Tag.id.in_(ids)).all()
            thread.tags = tags
    db.session.add(thread)
    db.session.flush()  # get thread.id

    # first comment = description
    first = ThreadComment(thread_id=thread.id, user_id=current_user.id, content=desc)
    db.session.add(first)
    db.session.commit()

    flash("Thread created.", "success")
    return redirect(url_for("views.view_thread", thread_id=thread.id))

# View a thread and its comments
@views.route("/contact/thread/<int:thread_id>", methods=['GET'])
def view_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    comments = ThreadComment.query.filter_by(thread_id=thread.id).order_by(ThreadComment.created_at.asc()).all()
    mentions_me_ids = set()
    if current_user.is_authenticated:
        uname = (current_user.username or '').lower()
        pat = re.compile(rf"(?<!\w)@{re.escape(uname)}(?!\w)", re.IGNORECASE)
        for c in comments:
            try:
                if pat.search(c.content or ''):
                    mentions_me_ids.add(c.id)
            except Exception:
                pass
    return render_template("thread.html", user=current_user, thread=thread, comments=comments, mentions_me_ids=mentions_me_ids)

# Add a comment to a thread
@views.route("/contact/thread/<int:thread_id>/comment", methods=['POST'])
@login_required
def add_thread_comment(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    if thread.locked:
        flash('Thread is locked. No new comments allowed.', 'error')
        return redirect(url_for('views.view_thread', thread_id=thread.id))
    content = (request.form.get('content') or '').strip()
    parent_id_raw = request.form.get('parent_id')
    parent_id = int(parent_id_raw) if parent_id_raw and parent_id_raw.isdigit() else None
    if len(content) < 2:
        flash('Comment must be at least 2 characters.', 'error')
        return redirect(url_for('views.view_thread', thread_id=thread.id))
    # Validate parent belongs to same thread
    parent = None
    if parent_id:
        parent = ThreadComment.query.filter_by(id=parent_id, thread_id=thread.id).first()
        if not parent:
            flash('Invalid reply target.', 'error')
            return redirect(url_for('views.view_thread', thread_id=thread.id))

    comment = ThreadComment(content=content, author=current_user, thread=thread, parent=parent)
    db.session.add(comment)
    db.session.flush()  # get comment.id before notifications

    notified_ids = set()
    # Reply notification to parent author
    if parent and parent.user_id != current_user.id:
        notif = Notification(
            user_id=parent.user_id,
            actor_id=current_user.id,
            thread_id=thread.id,
            comment_id=comment.id,
            kind='reply'
        )
        db.session.add(notif)
        notified_ids.add(parent.user_id)

    # Mentions: find @username in content
    for m in re.findall(r"@([A-Za-z0-9_]{1,32})", content):
        user = User.query.filter(func.lower(User.username) == m.lower()).first()
        if user and user.id != current_user.id and user.id not in notified_ids:
            notif = Notification(
                user_id=user.id,
                actor_id=current_user.id,
                thread_id=thread.id,
                comment_id=comment.id,
                kind='mention'
            )
            db.session.add(notif)
            notified_ids.add(user.id)

    db.session.commit()
    flash('Comment posted!', 'success')
    return redirect(url_for('views.view_thread', thread_id=thread.id))

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
        description = (request.form.get('description') or '').strip()[:250]
        if not file or not file.filename:
            flash('No file selected.', 'error')
            return redirect(url_for('views.gallery'))
        if not allowed_file(file.filename):
            flash('Unsupported file type.', 'error')
            return redirect(url_for('views.gallery'))

        # Enforce server-side size limit (5MB)
        size_ok = True
        size = None
        try:
            if getattr(file, 'content_length', None):
                size = file.content_length
            else:
                pos = file.stream.tell()
                file.stream.seek(0, os.SEEK_END)
                size = file.stream.tell()
                file.stream.seek(pos)
            size_ok = (size is None) or (size <= MAX_FILE_SIZE)
        except Exception:
            size_ok = True  # if unknown, allow; front-end already checks
        if not size_ok:
            flash('Image exceeds 5 MB.', 'error')
            return redirect(url_for('views.gallery'))

        # Create unique filename to avoid collisions
        import uuid
        from pathlib import Path
        ext = Path(file.filename).suffix.lower()
        unique_name = f"{uuid.uuid4().hex}{ext}"
        save_path = os.path.join(GALLERY_FOLDER, unique_name)

        try:
            file.save(save_path)
        except Exception:
            flash('Failed to save image.', 'error')
            return redirect(url_for('views.gallery'))

        # Set created_at as UTC and timezone-aware
        utc_now = datetime.now(pytz.utc)
        new_image = GalleryImage(
            filename=unique_name,
            uploader_id=current_user.id,
            description=description,
            created_at=utc_now
        )
        db.session.add(new_image)
        db.session.commit()
        flash('Image uploaded!', 'success')
        return redirect(url_for('views.gallery'))
    images = GalleryImage.query.order_by(GalleryImage.created_at.desc()).all()
    nz_tz = pytz.timezone('Pacific/Auckland')
    for img in images:
        # Ensure created_at is timezone-aware before converting
        if img.created_at.tzinfo is None:
            img.created_at = pytz.utc.localize(img.created_at)
        # Format for readability: e.g. "Tue, 13 Aug 2025, 03:45 PM"
        img.nzst = img.created_at.astimezone(nz_tz).strftime('%a, %d %b %Y, %I:%M %p')
    return render_template('gallery.html', images=images, user=current_user)

@views.route('/gallery/<int:image_id>/delete', methods=['POST'])
@login_required
def delete_gallery_image(image_id):
    img = GalleryImage.query.get_or_404(image_id)
    # Permissions: uploader, moderators/admins, or owner
    if not (current_user.is_authenticated and (current_user.id == img.uploader_id or current_user.can_moderate() or current_user.is_owner)):
        flash('You do not have permission to delete this image.', 'error')
        return redirect(url_for('views.gallery'))
    # Remove file from disk
    GALLERY_FOLDER = os.path.join(current_app.root_path, 'static', 'gallery')
    file_path = os.path.join(GALLERY_FOLDER, img.filename)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception:
        pass
    # Remove DB entry
    db.session.delete(img)
    db.session.commit()
    flash('Image deleted.', 'success')
    return redirect(url_for('views.gallery'))

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
@views.route('/about', methods=['GET'])
def about():
    # Classes in TF2 are fixed at 9; adjust if you model them separately
    total_classes = 9

    # Counts from your database
    total_images = GalleryImage.query.count()
    total_users = User.query.count()

    # Comments = Notes + ThreadComments (if you use forum threads)
    total_notes = Note.query.count()
    try:
        total_thread_comments = ThreadComment.query.count()
    except Exception:
        total_thread_comments = 0
    total_comments = total_notes + total_thread_comments

    return render_template(
        "about_page.html",
        user=current_user,
        total_classes=total_classes,
        total_images=total_images,
        total_users=total_users,
        total_comments=total_comments,
    )
