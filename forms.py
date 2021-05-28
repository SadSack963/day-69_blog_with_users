from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email, Length
# https://wtforms.readthedocs.io/en/2.3.x/validators/#module-wtforms.validators
# Email() requires WTForms email_validator package:
#       pip install wtforms[email]
from flask_ckeditor import CKEditorField


# WTForm
class CreatePostForm(FlaskForm):
    title = StringField(
        label="Blog Post Title",
        validators=[DataRequired()],
    )
    subtitle = StringField(
        label="Subtitle",
        validators=[DataRequired()],
    )
    img_url = StringField(
        label="Blog Image URL",
        validators=[DataRequired(), URL()],
    )
    body = CKEditorField(
        label="Blog Content",
        validators=[DataRequired()],
    )
    submit = SubmitField(
        label="Submit Post",
    )


class RegisterForm(FlaskForm):
    email = StringField(
        label="Email",
        validators=[DataRequired(), Email(check_deliverability=True)],
        render_kw={'style': 'width: 60ch'},
    )
    password = PasswordField(
        label="Password",
        validators=[DataRequired(), Length(min=6)],
        render_kw={'style': 'width: 60ch'},
    )
    name = StringField(
        label="Name",
        validators=[DataRequired()],
        render_kw={'style': 'width: 60ch'},
    )
    submit = SubmitField(
        label="Sign Me Up",
        render_kw={'btn-primary': 'True'}
    )


class LoginForm(FlaskForm):
    email = StringField(
        label="Email",
        validators=[DataRequired(), Email(check_deliverability=True)],
        render_kw={'style': 'width: 60ch'},
    )
    password = PasswordField(
        label="Password",
        validators=[DataRequired(), Length(min=6)],
        render_kw={'style': 'width: 60ch'},
    )
    submit = SubmitField(
        label="Log In",
        render_kw={'btn-primary': 'True'}
    )


class CommentForm(FlaskForm):
    body = CKEditorField(
        label="Your Comment",
        validators=[DataRequired()],
    )
    submit = SubmitField(
        label="Submit Comment",
        render_kw={'btn-primary': 'True'}
    )
