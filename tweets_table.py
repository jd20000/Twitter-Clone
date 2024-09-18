import sqlite3

# Connect to the SQLite database
db_path = 'C:/Users/jayde/OneDrive/Desktop/project/twitter_clone.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Step 1: Create a new table without the "image" column
create_new_table_sql = '''
CREATE TABLE tweets_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT,
    user_id INTEGER,
    created_at TIMESTAMP
);
'''
cursor.execute(create_new_table_sql)

# Step 2: Copy data from the old table to the new table
copy_data_sql = '''
INSERT INTO tweets_new (id, content, user_id, created_at)
SELECT id, content, user_id, created_at FROM tweets;
'''
cursor.execute(copy_data_sql)

# Step 3: Drop the old table
drop_old_table_sql = 'DROP TABLE tweets;'
cursor.execute(drop_old_table_sql)

# Step 4: Rename the new table to the original table name
rename_table_sql = 'ALTER TABLE tweets_new RENAME TO tweets;'
cursor.execute(rename_table_sql)

# Step 5: Add a new column "new_image" to the tweets table
add_new_column_sql = '''
ALTER TABLE tweets ADD COLUMN image TEXT;
'''
cursor.execute(add_new_column_sql)

# Commit changes and close the connection
conn.commit()
conn.close()

print("The 'image' column has been removed, and the new 'new_image' column has been added to the 'tweets' table.")
