from flask import Blueprint, render_template, redirect, url_for, flash,jsonify,request
from flask_login import login_user, logout_user, login_required 
from werkzeug.security import generate_password_hash, check_password_hash
from models import User,Tweet
from forms import LoginForm, RegistrationForm
from app import app
from init import login_manager,bcrypt,create_app

auth = Blueprint('auth', __name__)

########### PROFILE

   
###################



#update profile
# 
 """
@auth.route('/profile/<username>/update', methods=['POST'])
@login_required
def update_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user != current_user:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user.bio = request.form.get('bio', user.bio)
    db.session.commit()
    return redirect(url_for('routes.profile', username=user.username))
#gettweet
@auth.route('/profile/<username>/tweets', methods=['GET'])
@login_required
def get_tweets(username):
    user = User.query.filter_by(username=username).first_or_404()
    tweets = Tweet.query.filter_by(author=user).order_by(Tweet.timestamp.desc()).all()
    return jsonify([{'content': tweet.content, 'timestamp': tweet.timestamp} for tweet in tweets])

#######################################################


#################################################################
#signupp
@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('auth.login'))
    return render_template('signup.html', form=form)


#logout
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


#followw
@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user != current_user and not Follower.query.filter_by(follower_id=current_user.id, following_id=user.id).first():
        follow = Follower(follower_id=current_user.id, following_id=user.id)
        db.session.add(follow)
        db.session.commit()
    return redirect(url_for('profile', username=username))

#unfollow
@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first_or_404()
    follow = Follower.query.filter_by(follower_id=current_user.id, following_id=user.id).first()
    if follow:
        db.session.delete(follow)
        db.session.commit()
    return redirect(url_for('profile', username=username))


#like the twwweet
@app.route('/like/<int:tweet_id>')
@login_required
def like(tweet_id):
    tweet = Tweet.query.get_or_404(tweet_id)
    if not Like.query.filter_by(user_id=current_user.id, tweet_id=tweet_id).first():
        like = Like(user_id=current_user.id, tweet_id=tweet_id)
        db.session.add(like)
        db.session.commit()
    return redirect(url_for('home'))

#ulikeeee
@app.route('/unlike/<int:tweet_id>')
@login_required
def unlike(tweet_id):
    tweet = Tweet.query.get_or_404(tweet_id)
    like = Like.query.filter_by(user_id=current_user.id, tweet_id=tweet_id).first()
    if like:
        db.session.delete(like)
        db.session.commit()
    return redirect(url_for('home'))

#retweeett
@app.route('/retweet/<int:tweet_id>')
@login_required
def retweet(tweet_id):
    tweet = Tweet.query.get_or_404(tweet_id)
    if not Retweet.query.filter_by(user_id=current_user.id, tweet_id=tweet_id).first():
        retweet = Retweet(user_id=current_user.id, tweet_id=tweet_id)
        db.session.add(retweet)
        db.session.commit()
    return redirect(url_for('home'))
"""