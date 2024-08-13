import sqlite3
conn = sqlite3.connect("twitter_clone.db")
cursor = conn.cursor()

# Create users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    bio TEXT DEFAULT "",
    profile_picture TEXT DEFAULT "default.jpg"
)
''')

# Create tweets table
cursor.execute('''
CREATE TABLE IF NOT EXISTS tweets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users (id)
)
''')

# Create followers table
cursor.execute('''
CREATE TABLE IF NOT EXISTS followers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    follower_id INTEGER,
    following_id INTEGER,
    FOREIGN KEY (follower_id) REFERENCES users (id),
    FOREIGN KEY (following_id) REFERENCES users (id)
)
''')

# Create likes table
cursor.execute('''
CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    tweet_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (tweet_id) REFERENCES tweets (id)
)
''')

# Create retweets table
cursor.execute('''
CREATE TABLE IF NOT EXISTS retweets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    tweet_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (tweet_id) REFERENCES tweets (id)
)
''')

