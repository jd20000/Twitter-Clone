from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask import flash,redirect,url_for,render_template
from app import app
import sqlite3
from forms import RegistrationForm





login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['DATABASE'] = 'C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db'
    app.config['SECRET_KEY'] = '\xf0\xe9\x8d\xf4\x95\xa9\x16\x0e\x8f\x11\xa7\xfb\xbc\x9d\xdb\xcc\xe7\xd4\x93\xea\x7f\x12\x95\xf8'
   
    

    login_manager.init_app(app) 
    login_manager.login_view = 'login'  # Specify the login route

    @login_manager.user_loader
    def load_user(user_id):
        conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user  # You might need to adjust this based on your user object
############### INITIALIZIN LOGIN AS START 
       
################## HOME PAGE 
    from routes import auth
    app.register_blueprint(auth)

    return app
####################################################################################

    
    
