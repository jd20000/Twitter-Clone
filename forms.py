from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,BooleanField,ValidationError,TextAreaField,FileField
from wtforms.validators import DataRequired, Length,EqualTo,Email

class LoginForm(FlaskForm):
    username_or_email = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    remember = BooleanField('Remember Me')  # Optional: Include if you have a remember me feature


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password_hash = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password_hash', message='Passwords must match')])
    submit = SubmitField('Register')
    remember = BooleanField('Remember Me')

class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired()])
    bio = TextAreaField('Bio')
    profile_picture = FileField('Profile Picture')
    submit = SubmitField('Update')

class TweetForm(FlaskForm):
    tweetContent = TextAreaField('Tweet', validators=[DataRequired()])
    image = FileField('Image')
    submit = SubmitField('Tweet')   