from flask import Flask
from app import app  # Ensure this imports the Flask app from your main application module

if __name__ == '__main__':
    app.run(debug=True)

