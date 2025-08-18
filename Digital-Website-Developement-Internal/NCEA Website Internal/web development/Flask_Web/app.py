# import the create_app function
from website import create_app
from werkzeug.exceptions import RequestEntityTooLarge
from flask import redirect, url_for, flash, request

# run create app function as main

if __name__ == "__main__":
    app = create_app()
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB

    # Error handler for large file uploads
    @app.errorhandler(RequestEntityTooLarge)
    def handle_large_file(e):
        flash('File is too large (max 5 MB).', 'error')
        # Redirect back to the page the user was on, or home if not available
        return redirect(request.referrer or url_for('views.gallery'))

    app.run(debug=True)
