import os

from datetime import date, datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from profanity_filter import ProfanityFilter
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash


from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///final.db")

# Configure profanity filter
pf = ProfanityFilter()

## REGISTRATION, LOG IN , LOG OUT ##
# Register user
@app.route("/register", methods=["GET", "POST"])
def register():

    # Clear user_id
    session.clear()

    if request.method == "POST":
        # Query database for username
        dbusername = db.execute("SELECT username FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username is not already taken
        if len(dbusername) == 1:
            return apology("username is already taken", 400)

        # Ensure username was submitted
        elif not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password was reentered for confirmation
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Ensure password was confirmed correctly
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password does not match", 400)

        # Log user in after they successfully register
        elif request.form.get("password") == request.form.get("confirmation"):
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get(
                       "username"), generate_password_hash(request.form.get("password")))
            return login()

    # User reached route via GET
    else:
        return render_template("register.html")
        

# Log user in 
@app.route("/login", methods=["GET", "POST"])
def login():

    # Clear user_id
    session.clear()

    # User submits form
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reaches page by link
    else:
        return render_template("login.html")


# Log user out 
@app.route("/logout")
def logout():

    # Clear user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")
## END REGISTRATION, LOG IN , LOG OUT ##


## MAIN PAGES ##
# Home page (Posting and viewing content)
@app.route("/", methods=["GET", "POST"])
@login_required
def home():

    # When user submits a post
    if request.method == "POST":

        # Ensure title is included
        if not request.form.get("title"):
            return apology("must provide title", 400)

        # Ensure content of post is included
        elif not request.form.get("content"):
            return apology("Nothing is on your mind?", 400)

        else:
            # Get username of user from database
            user = db.execute ("SELECT username FROM users WHERE id = ?", session["user_id"])
            username = user[0]["username"]

            # Get title and content user posts (and filter offensive words)
            filtered_title = pf.censor(request.form.get("title"))
            filtered_content = pf.censor(request.form.get("content"))

            # Store title and content user posts in database
            db.execute("INSERT INTO posts (username, user_id, title, content) VALUES (?, ?, ?, ?)", username, session["user_id"], filtered_title, filtered_content)
            
            # Load all posts from database
            posts = db.execute("SELECT * FROM posts ORDER BY time DESC")

            return render_template("home.html", posts=posts)

    # User visits page without posting
    else:
        # Load all posts from database
        posts = db.execute("SELECT * FROM posts ORDER BY time DESC")

        return render_template("home.html", posts=posts)

# My Posts page (Viewing and deleting content)
@app.route("/my-posts", methods=["GET", "POST"])
@login_required
def my_posts():

    # When user submits a post
    if request.method == "POST":

        # Ensure title of post to be deleted is included
        if not request.form.get("delete-title"):
            return apology("must provide title of post you want to delete", 400)

        else:
            # Get title and content user posts (and filter offensive words)
            delete_title = request.form.get("delete-title")

            # Delete user's post from database
            db.execute("DELETE FROM posts WHERE title = ? AND user_id = ? ", delete_title, session["user_id"])

            # Load all posts from database         
            user_posts = db.execute("SELECT * FROM posts WHERE user_id = ? ORDER BY time DESC ", session["user_id"])

            return render_template("my_posts.html", user_posts=user_posts)

    # User visits page without posting
    else:
        # Load all posts from database         
        user_posts = db.execute("SELECT * FROM posts WHERE user_id = ? ORDER BY time DESC ", session["user_id"])

        return render_template("my_posts.html",  user_posts= user_posts)
## END MAIN PAGES ##


## SETTINGS ##
# Allow user to change password
@app.route("/password", methods=["GET", "POST"])
@login_required
def password():

    # User submits form
    if request.method == "POST":

        # Ensure current password is correct
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if not check_password_hash(user[0]["hash"], request.form.get("current_password")):
            return apology("wrong password", 400)

        # Ensure current password was submitted
        elif not request.form.get("current_password"):
            return apology("must provide current password", 400)

        # Ensure new password was submitted
        elif not request.form.get("new_password"):
            return apology("must provide new password", 400)

        # Ensure password was reentered for confirmation
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Ensure new password was confirmed correctly
        elif request.form.get("new_password") != request.form.get("confirmation"):
            return apology("new password does not match", 400)

        elif request.form.get("new_password") == request.form.get("confirmation"):
            db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(
                request.form.get("new_password")), session["user_id"])
            return render_template("pass_updated.html")

    # User reached route via GET
    else:
        return render_template("password.html")
## END SETTINGS ##
