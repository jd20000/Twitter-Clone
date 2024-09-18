# Twitter Clone Web Application

A web application that replicates core functionalities of Twitter using HTML/CSS/Tailwind for the frontend and Python with Jinja2 and SQLite for the backend.
## Table of Contents

- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Database Structure](#database-structure)
- [Project Structure](#project-structure)
- [Routes and Endpoints](#routes-and-endpoints)
- [Acknowledgments](#acknowledgments)

## Features

- User registration and login
- Posting and viewing tweets
- Viewing user profiles
- Following and unfollowing users
- Displaying follower and following counts
- Editing user profiles

## Technologies Used

- **Frontend:** HTML, CSS, Tailwind CSS
- **Backend:** Python, Flask, Jinja2
- **Database:** SQLite
- **Authentication:** JWT Tokens

## Installation

### Prerequisites

- Python 3.7 or higher
- SQLite

I have created and setup a virtual environment which is recommended so that the changes done inside the project file won't affect any other file in the global environment.



### To create a virtual environment on terminal

#### If on Linux

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m venv venv
venv\Scripts\activate

``` 
Configuration
The application uses a secret key for token generation and verification. You can find and modify it in the app.py file.

python
Copy code
app.config['SECRET_KEY'] = '\xf0\xe9\x8d\xf4\x95\xa9\x16\x0e\x8f\x11\xa7\xfb\xbc\x9d\xdb\xcc\xe7\xd4\x93\xea\x7f\x12\x95\xf8'

## Screenshots

![Login Page](https://github.com/jd20000/Twitter-Clone/blob/main/screenshots/Screenshot%20(312).png)
![Register Page](https://github.com/jd20000/Twitter-Clone/blob/main/screenshots/Screenshot%20(311).png)
![Home Page](https://github.com/jd20000/Twitter-Clone/blob/main/screenshots/Screenshot%20(313).png)
![Profile Page](https://github.com/jd20000/Twitter-Clone/blob/main/screenshots/Screenshot%20(314).png)
![Search User ](https://github.com/jd20000/Twitter-Clone/blob/main/screenshots/Screenshot%20(316).png)


