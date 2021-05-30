from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import backref, relationship, exc
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os
from functools import wraps
# Flask Debug-toolbar
# https://github.com/flask-debugtoolbar/flask-debugtoolbar
# https://flask-debugtoolbar.readthedocs.io/en/latest/
from flask_debugtoolbar import DebugToolbarExtension

API_KEY = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
DB_URL = 'sqlite:///database/blog.db'

#   =======================================
#           CONFIGURE FLASK APP
#   =======================================

"""
    DEFAULT FLASK APP CONFIGURATION
    ===============================
    default_config = {
        'APPLICATION_ROOT': '/',
        'DEBUG': None,
        'ENV': None,
        'EXPLAIN_TEMPLATE_LOADING': False,
        'JSONIFY_MIMETYPE': 'application/json',
        'JSONIFY_PRETTYPRINT_REGULAR': False,
        'JSON_AS_ASCII': True,
        'JSON_SORT_KEYS': True,
        'MAX_CONTENT_LENGTH': None,
        'MAX_COOKIE_SIZE': 4093,
        'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days = 31),
        'PREFERRED_URL_SCHEME': 'http',
        'PRESERVE_CONTEXT_ON_EXCEPTION': None,
        'PROPAGATE_EXCEPTIONS': None,
        'SECRET_KEY': None,
        'SEND_FILE_MAX_AGE_DEFAULT': None,
        'SERVER_NAME': None,
        'SESSION_COOKIE_DOMAIN': None,
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_NAME': 'session',
        'SESSION_COOKIE_PATH': None,
        'SESSION_COOKIE_SAMESITE': None,
        'SESSION_COOKIE_SECURE': False,
        'SESSION_REFRESH_EACH_REQUEST': True,
        'TEMPLATES_AUTO_RELOAD': None,
        'TESTING': False,
        'TRAP_BAD_REQUEST_ERRORS': None,
        'TRAP_HTTP_EXCEPTIONS': False,
        'USE_X_SENDFILE': False
    }
"""

app = Flask(__name__)
app.config['SECRET_KEY'] = API_KEY
ckeditor = CKEditor(app)
Bootstrap(app)

# Flask Debug-toolbar
app.debug = True
toolbar = DebugToolbarExtension(app)


#   =======================================
#              CONNECT TO DB
#   =======================================

app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


#   =======================================
#              FLASK LOGIN
#   =======================================

# https://flask-login.readthedocs.io/en/latest/
# YouTube video: https://www.youtube.com/watch?v=2dEM-s3mRLE
# Example: https://gist.github.com/bkdinoop/6698956
login_manager = LoginManager()  # Instantiate the Flask Login extension

# # Specify the default login URL in the Flask-Login
# login_manager.login_view = 'login'
# login_manager.login_message = u"Please log in to access this page."
# login_manager.setup_app(app)

login_manager.init_app(app)  # Initialise the manager passing the app to it


#   =======================================
#              CONFIGURE TABLES
#   =======================================

class User(UserMixin, db.Model):
    # A user can have many blog posts, but a post can only belong to one user.
    # This is a one-to-many relationship.
    # User is the PARENT, BlogPost is the CHILD.
    # https://docs.sqlalchemy.org/en/13/orm/basic_relationships.html
    # https://flask-sqlalchemy.palletsprojects.com/en/2.x/models/
    # https://www.youtube.com/watch?v=juPQ04_twtA

    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(1000), nullable=False)
    name = db.Column(db.String(100), nullable=False)

    # See Diagram at "docs/Class_Diagram.png"
    # https://www.reddit.com/r/flask/comments/142gqe/trying_to_understand_relationships_in_sqlalchemy/
    # The "posts" attribute for the User object is a list.
    # This list defines the relationship and it can be empty or contain zero or many objects.
    # To add a post to a user you'll define a user object, a post object and append the post object to user.posts.
    # The back_populates allows you to get the user object from a post object (post.user).
    # With back_populates, both sides of the relationship are defined explicitly

    # Create reference to the BlogPost class - "author" refers to the author property in the BlogPost class
    # posts is a "pseudo column" in this "users" table
    # For example, you could use user.posts to retrieve the list of posts that user has created
    posts = db.relationship('BlogPost', back_populates='author')  # refers to the child
    # Create reference to the Comments class - "commenter" refers to the commenter property in the Comments class
    # comments is a "psuedo column" in this "users" table
    # For example, you could use user.comments to retrieve the list of comments that user has created
    comments = db.relationship('Comment', back_populates='commenter')  # refers to the child


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # See Diagram at "docs/Class_Diagram.png"
    # Create ForeignKey "users.id" - refers to the tablename of User class
    # ForeignKey refers to the primary key in the other *table* (users)
    # author_id is a real column in this "blog_posts" table
    # Without the ForeignKey, the relationships would not work.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # Create reference to the User class - "posts" refers to the posts property in the User class
    # author is a "pseudo column" in this "blog_posts" table
    # For example, you could use blog_post.author to retrieve the user who created the post
    author = db.relationship('User', back_populates='posts')  # refers to the parent
    # Create reference to the Comment class - "post" refers to the post property in the Comment class
    # comments is a "pseudo column" in this "blog_post" table
    # For example, you could use blog_post.comments to retrieve the list of comments related to that post
    comments = db.relationship('Comment', back_populates='post')  # refers to the child


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(250), nullable=False)

    # See Diagram at "docs/Class_Diagram.png"
    # Create ForeignKey "blog_posts.id" - refers to the tablename of BlogPost class
    # ForeignKey refers to the primary key in the other *table* (blog_posts)
    # post_id is a real column in this "comments" table
    # Without the ForeignKey, the relationships would not work.
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'), nullable=False)
    # Create reference to the BlogPost class - "comments" refers to the comments property in the BlogPost class
    # post is a "pseudo column" in this "blog_posts" table
    # For example, you could use comment.post to retrieve the post associated with this comment
    post = db.relationship('BlogPost', back_populates='comments')  # refers to the parent
    # Create ForeignKey "user.id" - refers to the tablename of User class
    # ForeignKey refers to the primary key in the other *table* (users)
    # commenter_id is a real column in this "comments" table
    # Without the ForeignKey, the relationships would not work.
    commenter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # Create reference to the User class - "comments" refers to the comments property in the User class
    # commenter is a "pseudo column" in this "comments" table
    # For example, you could use comment.commenter to retrieve the user associated with this comment
    commenter = db.relationship('User', back_populates='comments')  # refers to the parent


# Create the database file if it doesn't exist - also used to create / modify tables
if not os.path.isfile(DB_URL):
    db.create_all()


#   =======================================
#                 DECORATORS
#   =======================================

@login_manager.user_loader
def load_user(user_id):
    """
    This callback is used to reload the user object from the user ID stored in the session.
    It connects the abstract user that Flask Login uses with the actual users in the model
    It should take the unicode ID of a user, and return the corresponding user object.

    It should return None (not raise an exception) if the ID is not valid.
    (In that case, the ID will manually be removed from the session and processing will continue.)

    :param user_id: unicode user ID
    :return: user object
    """
    return User.query.get(int(user_id))


def admin_only(f):
    # A decorator is a function that wraps and replaces another function.
    # Since the original function is replaced, you need to remember to copy
    # the original function’s information to the new function.
    # Use functools.wraps() to handle this for you.
    # https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/#login-required-decorator
    # https://flask.palletsprojects.com/en/1.1.x/patterns/errorpages/
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If user is not logged in or id is not 1 then return abort with 403 error
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)  # Forbidden
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


#   =======================================
#               ERROR HANDLER
#   =======================================

@app.errorhandler(403)
def forbidden(e):
    print(e)
    return render_template('403.html', error=e), 403


@app.errorhandler(404)
def forbidden(e):
    print(e)
    return render_template('404.html', error=e), 404


#   =======================================
#                  ROUTES
#   =======================================

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()  # WTF form for the web page
    if form.validate_on_submit():
        # Create a new user object
        user = User()
        user.email = form.email.data
        user.name = form.name.data

        # Check if the email is already registered
        if User.query.filter_by(email=user.email).first():
            flash(f"User {user.email} already exists!", 'info')
            flash("Log in instead.")
            return render_template("login.html", form=LoginForm())
        # Salt and Hash the password
        user.password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha3_512:100000',
            salt_length=32
        )
        # Save the user in the database
        db.session.add(user)
        db.session.commit()
        print(f'Registered new user: {user.name}')
        # Log the user in
        login_user(user)
        flash('Logged in successfully.', 'info')
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        email = form.email.data
        password = form.password.data
        # Make sure the user exists
        try:
            user = User.query.filter_by(email=email).first()
        except exc.NoResultFound:
            # SQLAlchemy.orm exception
            flash(f"User {email} not found!", 'error')
            flash(f"Try again.")
            print(f"SQLAlchemy.orm exception: User {email} not found!")
            return render_template("login.html", form=form)
        # print(user)
        if user:
            # Check the the hashed password in the database against the input password
            if check_password_hash(pwhash=user.password, password=password):
                # Log in and authenticate the user
                login_user(user)

                # Flash Messages will show on the page that is redirected to (redirect only, not render_template)
                # as long as the HTML is coded of course.
                # See flash.html which is included in other html pages: {% include 'flash.html' %}
                #   optional category: 'message', 'info', 'warning'. 'error'
                flash('Logged in successfully.', 'info')

                # Warning: You MUST validate the value of the next parameter.
                # If you do not, your application will be vulnerable to open redirects.
                #   Example: A logged out user enters the URL: http://127.0.0.1:5008/secrets
                #   /secrets is protected, so the user is redirected to the login page:
                #   http://127.0.0.1:5008/login?next=%2Fsecrets
                #   Once the user has logged in, we redirect to where they wanted to go using the "next" attribute
                # TODO: Handle the "next" parameter

                print(f'Login: user.name = {user.name}')

                return redirect(url_for('get_all_posts'))
            else:
                flash(f'Incorrect Password for {email}', 'error')
                flash(f"Try again.")
                return render_template("login.html", form=form)
        else:  # User == None
            flash(f"User {email} not found!", 'error')
            flash(f"Try again.")
            return render_template("login.html", form=form)
    return render_template("login.html", form=form)


# When applying further decorators, always remember that the route() decorator is always the outermost.
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        print(requested_post, current_user)
        new_comment = Comment(
            body=form.body.data,
            post=requested_post,
            commenter=current_user,
            date=date.today().strftime("%d/%b/%Y"),
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%d/%b/%Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5009, debug=True)
