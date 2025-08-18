#import external libaries
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy import text


db = SQLAlchemy()
DB_NAME = "database.db"

# create app function
# returns app


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'OF3n92fnemkr'
    # Make sure you have a DB URI set:
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_NAME}"
    db.init_app(app)

    # Optional: set your owner credentials here (change these!)
    app.config.setdefault('OWNER_EMAIL', 'ppgodess2020@email.com')
    app.config.setdefault('OWNER_USERNAME', 'Himothy')
    app.config.setdefault('OWNER_PASSWORD', 'password67')

    # import views from views.py
    from .views import views
    from .auth import auth

    # register blueprints
    app.register_blueprint(views, url_prefix="/")
    app.register_blueprint(auth, url_prefix="/")
    
    
    # login manager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .models import User  # delayed import to avoid circular

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    with app.app_context():
        db.create_all()
        _run_light_migrations()  # <--- add this call here
        _seed_owner(app)

    return app

def _seed_owner(app):
    from .models import User
    # If an owner already exists, skip
    if User.query.filter_by(role='owner').first():
        return
    email = app.config['OWNER_EMAIL']
    username = app.config['OWNER_USERNAME']
    password = app.config['OWNER_PASSWORD']

    # If email/username taken, don’t overwrite; only create if both free
    if User.query.filter((User.email == email) | (User.username == username)).first():
        return
    owner = User(email=email, username=username, role='owner', title='Owner')
    owner.set_password(password)
    db.session.add(owner)
    db.session.commit()

def _run_light_migrations():
    """SQLite-safe: add columns if missing."""
    with db.engine.begin() as conn:
        # user.role
        try:
            conn.execute(text("SELECT role FROM user LIMIT 1"))
        except Exception:
            conn.exec_driver_sql(
                "ALTER TABLE user ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'member'"
            )
        # user.title
        try:
            conn.execute(text("SELECT title FROM user LIMIT 1"))
        except Exception:
            conn.exec_driver_sql(
                "ALTER TABLE user ADD COLUMN title VARCHAR(60)"
            )
        # note.pinned
        try:
            conn.execute(text("SELECT pinned FROM note LIMIT 1"))
        except Exception:
            conn.exec_driver_sql(
                "ALTER TABLE note ADD COLUMN pinned BOOLEAN NOT NULL DEFAULT 0"
            )