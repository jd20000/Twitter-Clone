from flask import Flask, render_template, redirect, url_for, flash,jsonify,session,request,abort,make_response,g,send_from_directory
from forms import LoginForm, RegistrationForm,EditProfileForm,TweetForm
from flask_login import login_user, logout_user, login_required,current_user
from flask import flash,redirect,url_for,render_template
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
import datetime

from functools import wraps
from datetime import datetime, timedelta
import sqlite3
import os

from flask_login import LoginManager
login_manager = LoginManager()
#######

app = Flask(__name__)
app.config['WTF_CSRF_ENABLED'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = '\xf0\xe9\x8d\xf4\x95\xa9\x16\x0e\x8f\x11\xa7\xfb\xbc\x9d\xdb\xcc\xe7\xd4\x93\xea\x7f\x12\x95\xf8'
app.config['UPLOAD_FOLDER'] =   'templates/profile_pics'

SECRET_KEY = '\xf0\xe9\x8d\xf4\x95\xa9\x16\x0e\x8f\x11\xa7\xfb\xbc\x9d\xdb\xcc\xe7\xd4\x93\xea\x7f\x12\x95\xf8'
########################
def generate_token(user_id):
    try:
        payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1)
        }
        token= jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        return token
    except Exception as e:
        print(f"Error generating token: {e}")
        return None


def decode_token(token):
    try:
        print(token)
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        #user_id=payload.get('user_id')
        #if isinstance(user_id, int) or isinstance(user_id, str):
        return payload
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return None  # Token has expired
    except jwt.InvalidTokenError:
        print("Invalid token")
        return None  # Token is invalid
     
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('session')
        if not token:
            return jsonify({'message': 'Token is missing! token required'}), 401

        decoded_token = decode_token(token)
        if 'error' in decoded_token:
            return jsonify({'error': decoded_token['error']}), 401    

        user_id = decoded_token.get('user_id')
        if not user_id:
            return jsonify({'error': 'User ID is missing from token'}), 401

        g.current_user = user_id
        return f(*args, **kwargs)
    return decorated_function
   
##########################

bcrypt = Bcrypt()





#########################
@app.route('/api/user', methods=['GET'])
def get_user():
    token = request.cookies.get('session')  # Assuming the token is stored in a cookie named 'authToken'
    
    if not token:
        print("Token is missing from the cookies get user.")
        abort(401, description="Token is missing")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            raise jwt.InvalidTokenError("User ID missing from token")
        
        # Fetch user information based on user_id
        conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
        conn.row_factory = sqlite3.Row  # This allows rows to be accessed like dictionaries
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return jsonify({'username': user['username']})
        else:
            abort(404, description="User not found")
    
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        abort(401, description="Token has expired")
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        abort(401, description="Invalid token")

######  PHOTO UPLOADS 
UPLOAD_FOLDER = 'templates/profile_pics'
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/profile_pics/<filename>')
def profile_pics(filename):
    try:
        return os.path.join(UPLOAD_FOLDER, filename)
    except FileNotFoundError:
        abort(404)



@app.route('/', methods=['GET', 'POST'])
def index():
    return redirect(url_for('login')) 
####### HOME 
@app.route('/home', methods=['GET', 'POST'])
def home():
    token = request.cookies.get('session')  # Get token from the 'session' cookie

    # Validate token
    if not token:
        print("Token is missing home start")
        abort(401, description="Token is missing")  
    
    try:
        g.current_user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = g.current_user
        if not user_id:
            raise jwt.InvalidTokenError("User ID missing from token")
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        abort(401, description="Token has expired")
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        abort(401, description="Invalid token")
    
    form = TweetForm()
    if form.validate_on_submit():
        content = form.tweetContent.data
        try:
            conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
            conn.row_factory = sqlite3.Row 
            cursor = conn.cursor()
        
            cursor.execute('''
                INSERT INTO tweets (content, user_id)
                VALUES (?, ?)
                ''', (content, g.current_user,))
        
            conn.commit()
            conn.close()
            flash('Tweet posted successfully!', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            print(f"Error posting tweet: {e}")
            abort(500, description="Error posting tweet")

    ## FETCHING TWEETS 
    try:
        conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
        conn.row_factory = sqlite3.Row 
        cursor = conn.cursor()    
        cursor.execute('''
            SELECT tweets.id, tweets.content, tweets.created_at, users.username
            FROM tweets
            JOIN users ON tweets.user_id = users.id
            ORDER BY tweets.created_at DESC
        ''')
        tweets = cursor.fetchall()         
        conn.close()
    except Exception as e:
        print(f"Error fetching tweets: {e}")
        abort(500, description="Error fetching tweets")
    
    return render_template('home.html', tweets=tweets,user=g.current_user, form=form)
    
# USING NORMAL DATABASE CONNECTIVITY
def get_db_connection():
    conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
    conn.row_factory = sqlite3.Row  # Allows access to columns by name
    return conn
#########
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#########################
## REGISTERR DONEEE
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    print(type(datetime))
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password_hash = form.password_hash.data   
        hashed_password = generate_password_hash(password_hash)
        conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            # Insert new user into the users table
           
            cursor.execute('''
                    INSERT INTO users (username, email, password_hash)
                    VALUES (?, ?, ?)
                    ''', (username, email,hashed_password))
                   
            # Commit changes
            conn.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'danger')
        finally:
            # Close the connection
            conn.close()
    
    return render_template('register.html', form=form)

##########################
 ## LOGIN DONEE
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email')
        password = request.form.get('password')

        print(f"Username/Email: {username_or_email}")

        conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()        
        try:
            print(f"Username/Email: {username_or_email}") 
            # Find the user by username or email
            cursor.execute('''
                SELECT * FROM users WHERE username = ? OR email = ?
                ''', (username_or_email, username_or_email))
            user = cursor.fetchone()

            if user:
                print(f"User found: {user}")
                print(f"Stored hash: {user['password_hash']}")
                print(f"Entered password: {password}")

                if check_password_hash(user['password_hash'], password):
                    print("Password matches.")
                    user_id = user['id']
                    token = generate_token(user_id)
                    print(f"Generated Token: {token}")  # Generate the token                 
                    response = make_response(jsonify({'message': 'Login successful', 'home_url': url_for('home')}), 200)
                    response.set_cookie('session', token, httponly=True, secure=True, samesite='Lax')
                    return response
                    #conn.close()
                    #return jsonify({'token': token}), 200
                else:
                    print("Password does not match")
            else:
                print("User not found")
            return jsonify({'message': 'Invalid credentials'}), 401
             
        except sqlite3.Error as e:
            flash(f'An error occurred: {e}', 'danger')
        finally:
            # Close the connection
            conn.close()
    
    return render_template('login.html', form=form)
##################
@app.route('/api/logout', methods=['POST'])
def logout():
    response = jsonify({'message': 'Logged out successfully'})
    response.delete_cookie('authToken')  # Clear the token from cookies if used
    return response
## PROFILEE 
@app.route('/profile/<username>', methods=['GET'])
@token_required 
def profile(username):
    token = request.cookies.get('session')
    decoded_token = decode_token(token)
    user_id = decoded_token.get('user_id')
    
     

    conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

   
    cursor.execute('''SELECT * FROM users WHERE username = ?''', (username,))#ADDED COMMA CAUSE IF I DONT SQLITE WILL CONSIDER IT AS STRING WHICH IT DONT SUPPORT 
    user = cursor.fetchone()

    if user is None:
        return jsonify({'error': 'User not found'}), 404

    cursor.execute('''SELECT * FROM tweets WHERE user_id = ?''', (user_id,))
    tweets = cursor.fetchall()

    # Count the number of followers (users who follow the current user)
    cursor.execute('''SELECT COUNT(*) as follower_count FROM followers WHERE following_id = ?''', (user_id,))
    follower_count = cursor.fetchone()['follower_count']

    # Count the number of users the current user is following
    cursor.execute('''SELECT COUNT(*) as following_count FROM followers WHERE follower_id = ?''', (user_id,))
    following_count = cursor.fetchone()['following_count']

    cursor.execute('''
    SELECT tweets.*, retweets.user_id as retweet_user_id
    FROM tweets
    LEFT JOIN retweets ON tweets.id = retweets.tweet_id
    WHERE tweets.user_id = ? OR retweets.user_id = ?
    ORDER BY tweets.created_at DESC
    ''', (user['id'], user['id']))

    tweets = cursor.fetchall()
    

    conn.close()

    return render_template('profile.html', user=user, tweets=tweets, follower_count=follower_count,following_count=following_count)   
    
          
@app.route('/edit_profile/<username>', methods=['GET', 'POST'])
def edit_profile(username):
    

    conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()
    
    
    cursor.execute('''SELECT * FROM users WHERE username = ?''', (username,))
    user = cursor.fetchone()
    

    if user is None:
        flash('User not found.', 'danger')
        return redirect(url_for('home'))

    form = EditProfileForm(obj=user)

    if form.validate_on_submit():
        # Fetch form data
        new_username = form.username.data
        email = form.email.data
        bio = form.bio.data
        profile_picture = form.profile_picture.data

        if profile_picture and allowed_file(profile_picture.filename):
            filename = secure_filename(profile_picture.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            profile_picture.save(file_path)
        else:
            filename = 'default.jpg'  # Use a default picture if no file is uploaded


    
       
            # Update user information in the database
            cursor.execute('''
                UPDATE users
                SET username = ?, email = ?, bio = ?, profile_picture = ?
                WHERE username = ?
            ''', (new_username, email, bio, filename, username))
            conn.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile', username=new_username))
    if user:
        form.username.data = user['username']
        form.email.data = user['email']
        form.bio.data = user['bio']
        # No need to set profile_picture.data

    return render_template('edit_profile.html', form=form,user=user)
###################

##### FETCHING THE TWEEEETS FROM THE HOME  
@app.route('/api/tweets', methods=['GET', 'POST'])
def handle_tweets():
    # Extract token from cookies
    token = request.cookies.get('session')
    print('Token received for handle_tweets:', token)

    # Decode token if present
    user_id = None
    if token:
        token = token.strip()  
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('user_id')if payload else None
            print('Decoded user_id:', user_id)
            if not user_id:
                raise jwt.InvalidTokenError("User ID missing from token")
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': f'Invalid token: {str(e)}'}), 401
    else:
        return jsonify({'error': 'Token is missing '}), 401
    if request.method == 'POST':
        content = request.json.get('content')
        if not content:
            return jsonify({'error': 'Content cannot be empty'}), 400

        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401

        conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT INTO tweets (content, user_id, created_at)
                VALUES (?, ?, ?)
            ''', (content, user_id, datetime.utcnow()))
            conn.commit()
            return jsonify({'message': 'Tweet posted successfully!'}), 201
        except sqlite3.Error as e:
            conn.rollback()
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()

    elif request.method == 'GET':
        conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT tweets.id, tweets.content,tweets.created_at, users.username, user_id
                FROM tweets
                JOIN users ON tweets.user_id = users.id
                ORDER BY tweets.created_at DESC
            ''')
            tweets = cursor.fetchall()

            tweets_list = [{

                'id': tweet['id'],  # Corrected key here
                'content': tweet['content'],
                'created_at': tweet['created_at'],
                'username': tweet['username'],
                'user_id': tweet['user_id']
            } for tweet in tweets]
            return jsonify(tweets_list), 200
        except sqlite3.Error as e:
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()
########################################################
## LIKING A TWEET API 

@app.route('/api/tweets/like', methods=['POST'])
def like_tweet():
    token = request.cookies.get('session')
    print(f'Token: {token}')
    if not token:
        return jsonify({'error': 'Token is missing'}), 401
    decoded_token = decode_token(token)
    print(f'Decoded Token: {decoded_token}')
    if 'error' in decoded_token:
        return jsonify({'error': decoded_token['error']}), 401
    user_id = decoded_token.get('user_id')
    print(user_id)
    if not user_id:
        return jsonify({'error': 'User ID is missing from token'}), 401        
    data = request.get_json()
    tweet_id = data.get('tweetId')
    print(tweet_id)
    if not tweet_id:
        return jsonify({'error': 'Tweet ID is required'}), 400

    conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor() 

    try:   
        cursor.execute('SELECT * FROM tweets WHERE id = ?', (tweet_id,))
        tweet = cursor.fetchone()
        if not tweet:
            conn.close()
            return jsonify({'error': 'Tweet not found'}), 404

        cursor.execute('SELECT * FROM likes WHERE user_id = ? AND tweet_id = ?', (user_id, tweet_id))
        existing_like = cursor.fetchone()
        if existing_like:
            conn.close()
            return jsonify({'message': 'Tweet already liked'}), 400

        cursor.execute('INSERT INTO likes (user_id, tweet_id) VALUES (?, ?)', (user_id, tweet_id))
        conn.commit()
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

    return jsonify({'message': 'Tweet liked successfully'})

## UNLIKING A TWEET 
@app.route('/api/tweets/unlike', methods=['POST'])
@token_required
def unlike_tweet():
    token = request.cookies.get('session')
    data = request.get_json()
    tweet_id = data.get('tweetId')
    if not tweet_id:
        return jsonify({'error': 'Tweet ID is required'}), 400
    decoded_token = decode_token(token)
    user_id = decoded_token.get('user_id')
    conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor() 
    
    # Check if the tweet exists
    cursor.execute('SELECT * FROM tweets WHERE id = ?', (tweet_id,))
    tweet = cursor.fetchone()
    if not tweet:
        conn.close()
        return jsonify({'error': 'Tweet not found'}), 404

    # Check if the like exists
    cursor.execute('SELECT * FROM likes WHERE user_id = ? AND tweet_id = ?', (user_id, tweet_id))
    existing_like = cursor.fetchone()
    if not existing_like:
        conn.close()
        return jsonify({'message': 'Like not found'}), 400

    # Remove the like
    cursor.execute('DELETE FROM likes WHERE user_id = ? AND tweet_id = ?', (user_id, tweet_id))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Tweet unliked successfully'})


## RETWEET
@app.route('/api/tweets/retweet', methods=['POST'])
@token_required
def retweet_tweet():
    token = request.cookies.get('session')
    data = request.get_json()
    tweet_id = data.get('tweetId')   # The ID of the tweet being retweeted
    decoded_token = decode_token(token)
    user_id = decoded_token.get('user_id')
    if not tweet_id:
        return jsonify({'error': 'Tweet ID is required'}), 400

    conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor() 
     
    #
    cursor.execute('SELECT * FROM retweets WHERE user_id = ? AND tweet_id = ?', (user_id, tweet_id))
    existing_retweet = cursor.fetchone()

    if existing_retweet:
        conn.close()
        return jsonify({'message': 'Tweet already retweeted'}), 400
    #

    # Add the retweet
    cursor.execute('INSERT INTO retweets (user_id, tweet_id) VALUES (?, ?)', (user_id, tweet_id))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Tweet retweeted successfully'})


## UNDO RETWEET 
@app.route('/api/tweets/undo_retweet', methods=['POST'])
@token_required
def undo_retweet():
    token = request.cookies.get('session')
    data = request.get_json()
    tweet_id = data.get('tweetId')
    if not tweet_id:
        return jsonify({'error': 'Tweet ID is required'}), 400
    
    decoded_token = decode_token(token)
    user_id = decoded_token.get('user_id')

    conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor() 
     
    # Check if the tweet exists
    cursor.execute('SELECT * FROM tweets WHERE id = ?', (tweet_id,))
    tweet = cursor.fetchone()
    if not tweet:
        conn.close()
        return jsonify({'error': 'Tweet not found'}), 404

    # Check if the retweet exists
    cursor.execute('SELECT * FROM retweets WHERE user_id = ? AND tweet_id = ?', (user_id, tweet_id))
    existing_retweet = cursor.fetchone()
    if not existing_retweet:
        conn.close()
        return jsonify({'message': 'Retweet not found'}), 400

    # Remove the retweet
    cursor.execute('DELETE FROM retweets WHERE user_id = ? AND tweet_id = ?', (user_id, tweet_id))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Retweet undone successfully'})

########### FOLLOW 
@app.route('/api/users/follow', methods=['POST'])
@token_required
def follow_user():  
    token = request.cookies.get('session')
    data = request.get_json()
    userID  = data.get('userID')  # Updated key
    print(f'user id for follow user : {userID}' )   
    decoded_token = decode_token(token)
    u_id = decoded_token.get('user_id')
    print(f'Follower id : {u_id}')
    if not userID :
        return jsonify({'error': 'User ID to follow is required'}), 400

    conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Check if the user is already following
    cursor.execute('SELECT * FROM followers WHERE follower_id = ? AND following_id = ?',
                   (u_id, userID ))
    existing_follow = cursor.fetchone()

    if existing_follow:
        conn.close()
        return jsonify({'message': 'You are already following this user'}), 200

    # Insert the follow relationship
    cursor.execute('INSERT INTO followers (follower_id, following_id) VALUES (?, ?)',
                   (u_id, userID ))
    conn.commit()
    conn.close()

    return jsonify({'message': 'User followed successfully'})
############  UNFOLLOW
@app.route('/api/users/unfollow', methods=['POST'])
@token_required
def unfollow_user():
    token = request.cookies.get('session')
    data = request.get_json()
    userID  = data.get('userID')  # Updated key
    print(userID)
    if not userID :
        return jsonify({'error': 'User ID to unfollow is required'}), 300
     
    decoded_token = decode_token(token)
    u_id = decoded_token.get('user_id')
    print(f'Follower id : {u_id}')

    conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Check if the follow relationship exists
    cursor.execute('SELECT * FROM followers WHERE follower_id = ? AND following_id = ?',
                   (u_id, userID ))
    existing_follow = cursor.fetchone()

    if not existing_follow:
        conn.close()
        return jsonify({'message': 'You are not following this user'}), 300

    # Delete the follow relationship
    cursor.execute('DELETE FROM followers WHERE follower_id = ? AND following_id = ?',
                   (u_id, userID ))
    conn.commit()
    conn.close()

    return jsonify({'message': 'User unfollowed successfully'})

############## SEARCH FUNCITONALITY 
@app.route('/api/search/tweets', methods=['GET'])
@token_required
def search_tweets():
    query = request.args.get('query', '')
    
    if not query:
        return jsonify({'error': 'Search query is required'}), 400
    
    conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Search tweets by content
    cursor.execute("SELECT tweets.id, tweets.content, users.username FROM tweets JOIN users ON tweets.user_id = users.id WHERE tweets.content LIKE ?", ('%' + query + '%',))
    results = cursor.fetchall()
    
    conn.close()
    
    tweets = [{'id': row['id'], 'content': row['content'], 'username': row['username']} for row in results]
    
    return jsonify(tweets)

@app.route('/api/search/users', methods=['GET'])
@token_required
def search_users():
    query = request.args.get('query', '')
    
    if not query:
        return jsonify({'error': 'Search query is required'}), 400
    
    conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Search users by username
    cursor.execute('''
    SELECT id, username, bio, profile_picture
    FROM users
    WHERE username LIKE ?
''', ('%' + query + '%',))
    users  = cursor.fetchall()
    
    conn.close()
    
    user_data = [{'id': row['id'], 'username': row['username'], 'bio': row['bio'], 'profile_picture': row['profile_picture']} for row in users]
    
    return jsonify(user_data)

    #### ENDPOINT TO PIN POINT A SPECIFIC USER 
@app.route('/api/users/<int:user_id>', methods=['GET'])
@token_required
def get_user_details(user_id):
    conn = sqlite3.connect('C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get user details
    cursor.execute("SELECT id, username, bio, profile_image_url FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    
    # Get user's tweets
    cursor.execute("SELECT id, content, created_at FROM tweets WHERE user_id = ?", (user_id,))
    tweets = cursor.fetchall()
    
    conn.close()
    
    user_details = {
        'id': user['id'],
        'username': user['username'],
        'bio': user['bio'],
        'profile_image_url': user['profile_image_url'],
        'tweets': [{'id': tweet['id'], 'content': tweet['content'], 'created_at': tweet['created_at']} for tweet in tweets]
    }
    
    return jsonify(user_details)
