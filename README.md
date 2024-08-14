# Twitter Clone Web Application

A web application that replicates core functionalities of Twitter using HTML/CSS/Tailwind for the frontend and Python with Jinja2 and SQLite for the backend.
![Twitter Clone Banner](https://via.placeholder.com/1200x300.png?text=Twitter+Clone)

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


###  Testing Your README
- Commit the formatted `README.md` to your repository.
- Refresh the repository page on GitHub to see the updated README with the correct formatting.

###  Additional Tips
- **Use Online Markdown Editors**: Tools like [StackEdit](https://stackedit.io/) or [Dillinger](https://dillinger.io/) provide live previews.
- **Markdown Preview in Editors**: IDEs like VSCode have Markdown preview features built-in.

By following these tips, your `README.md` should display properly on GitHub. If issues persist, you can also directly view the rendered HTML or Markdown to identify specific formatting errors.


Configuration
The application uses a secret key for token generation and verification. You can find and modify it in the app.py file.

python
Copy code
app.config['SECRET_KEY'] = 'your_secret_key'
