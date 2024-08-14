Twitter Clone Web Application
A web application that replicates core functionalities of Twitter using HTML/CSS/Tailwind for the frontend and Python with Jinja2 and SQLite for the backend.

Table of Contents
    Features
    Technologies Used
    Installation
    Configuration
    Usage
    Database Structure
    Project Structure
    Routes and Endpoints
    Acknowledgments
    
  Features
    User registration and login
    Posting and viewing tweets
    Viewing user profiles
    Following and unfollowing users
    Displaying follower and following counts
    Editing user profiles
  Technologies Used
    Frontend: HTML, CSS, Tailwind CSS
    Backend: Python, Flask, Jinja2
    Database: SQLite
    Authentication: JWT Tokens
  Installation
    Prerequisites
    Python 3.7 or higher
    SQLite

  I have created and setup  an virtual environment which is recommended so that the changes done inside the project file won't affect any other file in the global environment
  to create a virtual environment on terminal bash :
    #IF ON LINUX 
    python3 -m venv venv
    source venv/bin/activate
    #IF ON WINDOWS 
    python3 -m venv venv
    venv\Scripts\activate

    
  Configuration
    The application uses a secret key for token generation and verification. You can find and modify it in the app.py file.
    app.config['SECRET_KEY'] = 'your_secret_key'

  Usage
    Access the application at http://localhost:5000 in your web browser.
    Register a new account or log in with an existing one.
    Use the navigation to explore and interact with the application's features.
    
  Database Structure
    Here's a summary of the database tables used in this project:

   Users
    Column  |	Type  |	Description
    id	    |INTEGER|	Primary key
    username|	TEXT	| User's unique username
    email	  |TEXT	  | User's email address
    password|	TEXT	| User's password (hashed)
    profile_picture|	TEXT |	URL to the user's profile picture
  Tweets
    Column |	Type |	Description
    id	| INTEGER	 | Primary key
    user_id |	INTEGER |	ID of the user who posted the tweet
    content |	TEXT |	The content of the tweet
    created_at |	DATETIME |	The timestamp of the tweet
  Followers
    Column |	Type |	Description
    id |	INTEGER  |	Primary key
    follower_id |	INTEGER	 |ID  of the user who is following
    following_id| 	INTEGER	|ID of the user being followed

  Project Structure
    app.py: Main application file containing the Flask app and routes.
    templates/: Contains HTML templates for the application.
    sqlite.py: Contains database initialization and query functions.
    forms.py: Contains all the forms required
    init.py : contains initialization codes
    run.py : Contains the code that will make the project run "python run.py"

  Acknowledgments
    Thanks to the developers of Flask, Tailwind CSS, and all the libraries used in this project.
    Inspired by the functionalities and design of Twitter.

    
    
    
