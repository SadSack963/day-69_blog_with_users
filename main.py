from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import orm
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm
from flask_gravatar import Gravatar
import os


API_KEY = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
DB_URL = 'sqlite:///database/blog.db'

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

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Login
# https://flask-login.readthedocs.io/en/latest/
# YouTube video: https://www.youtube.com/watch?v=2dEM-s3mRLE
# Example: https://gist.github.com/bkdinoop/6698956
login_manager = LoginManager()  # Instantiate the Flask Login extension

# # Specify the default login URL in the Flask-Login
# login_manager.login_view = 'login'
# login_manager.login_message = u"Please log in to access this page."
# login_manager.setup_app(app)

login_manager.init_app(app)  # Initialise the manager passing the app to it


# CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(1000), nullable=False)
    name = db.Column(db.String(100), nullable=False)


# Create the database file and tables
if not os.path.isfile(DB_URL):
    db.create_all()


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


#   =======================================
#                  ROUTES
#   =======================================

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    user_id = None
    username = request.args.get('username')
    user = User.query.filter_by(name=username).first()
    if user:
        user_id = user.id
    return render_template("index.html", all_posts=posts, id=user_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()  # WTF form for the web page
    if form.validate_on_submit():
        print("registering")
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
        # Log the user in
        login_user(user)
        flash('Logged in successfully.', 'info')
        return redirect(url_for('get_all_posts', username=user.name))
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
        except orm.exc.NoResultFound:
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

                return redirect(url_for('get_all_posts', username=user.name))
            else:
                flash(f'Incorrect Password for {email}', 'error')
                flash(f"Try again.")
                return render_template("login.html", form=form)
        else:  # User == None
            flash(f"User {email} not found!", 'error')
            flash(f"Try again.")
            return render_template("login.html", form=form)
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post")
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
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
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5009, debug=True)
