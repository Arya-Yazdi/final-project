import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from profanity_filter import ProfanityFilter
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash


from helpers import login_required

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
            error_username_taken = "*Username is already taken :("
            return render_template("register.html", error_username_taken=error_username_taken)

        # Ensure username was submitted
        elif not request.form.get("username"):
            error_no_username = "*Please type in a username"
            return render_template("register.html", error_no_username=error_no_username)

        # Ensure password was submitted
        elif not request.form.get("password"):
            error_password = "*Please type in your password"
            return render_template("register.html", error_password=error_password)

        # Ensure password was reentered for confirmation
        elif not request.form.get("confirmation"):
            error_reenter_password = "*Please reenter your password"
            return render_template("register.html", error_reenter_password=error_reenter_password)

        # Ensure password was confirmed correctly
        elif request.form.get("password") != request.form.get("confirmation"):
            error_password_match = "*Passwords do not match"
            return render_template("register.html", error_password_match=error_password_match)

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
            error_no_username = "*Please type in your username"
            return render_template("login.html", error_no_username=error_no_username)

        # Ensure password was submitted
        elif not request.form.get("password"):
            error_password = "*Please type in your password"
            return render_template("login.html", error_password=error_password)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            error_invalid = "*Invalid password / username"
            return render_template("login.html", error_invalid=error_invalid)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reaches page by link
    else:
        return render_template("login.html")


# Log user out 
@app.route("/logout", methods=["GET", "POST"])
def logout():

    if request.method == "POST":
        # Clear user_id
        session.clear()

        # Redirect user to login form
        return redirect("/")

    else:
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

        title = request.form.get("title")
        content = request.form.get("content")

        # Ensure title is included
        if not request.form.get("title"):
            error_title = "*Add a title"

            # Load all posts from database
            posts = db.execute("SELECT * FROM posts ORDER BY time DESC")

            return render_template("home.html", error_title=error_title, posts=posts, content=content)

        # Ensure content of post is included
        elif not request.form.get("content"):
            error_content = "Nothing is on your mind?"

            # Load all posts from database
            posts = db.execute("SELECT * FROM posts ORDER BY time DESC")

            return render_template("home.html", error_content=error_content, posts=posts, title=title)

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

# My posts page (Viewing and deleting content)
@app.route("/my-posts", methods=["GET", "POST"])
@login_required
def my_posts():

    # When user submits a post
    if request.method == "POST":

        # Ensure title of post to be deleted is included
        if not request.form.get("delete-title"):
            error_delete_title = "*Type in title of post you want to delete"

            # Load all posts from database 
            user_posts = db.execute("SELECT * FROM posts WHERE user_id = ? ORDER BY time DESC ", session["user_id"])

            return render_template("my_posts.html", error_delete_title=error_delete_title, user_posts= user_posts)

        delete_title = request.form.get("delete-title")
        rows = db.execute("SELECT * FROM posts WHERE  title = ? AND user_id = ? ", delete_title, session["user_id"])

        if len(rows) == 0:
            error_invalid_title = "*You don't have a post with such title"

            # Load all posts from database         
            user_posts = db.execute("SELECT * FROM posts WHERE user_id = ? ORDER BY time DESC ", session["user_id"])

            return render_template("my_posts.html", error_invalid_title=error_invalid_title, user_posts= user_posts)

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
# Load settings page
@app.route("/setting")
@login_required
def setting():
    user = db.execute ("SELECT * FROM users WHERE id = ?", session["user_id"])
    username = user[0]["username"]
    created = user[0]["time"]

    post_length = len(db.execute ("SELECT * FROM posts WHERE user_id = ?", session["user_id"]))
    return render_template("setting.html", username=username, created=created, post_length=post_length)

# Allow user to change password
@app.route("/password", methods=["GET", "POST"])
@login_required
def password():

    # User submits form to change password
    if request.method == "POST":


        # Ensure current password was submitted
        if not request.form.get("current_password"):
            error_password = "*Please type in your password"
            return render_template("setting.html", error_password=error_password)

        # Ensure current password is correct
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if not check_password_hash(user[0]["hash"], request.form.get("current_password")):
            error_wrong_password = "*Incorrect password"
            return render_template("setting.html", error_wrong_password=error_wrong_password)

        # Ensure new password was submitted
        elif not request.form.get("new_password"):
            error_new_password = "*Please type in your new password"
            return render_template("setting.html", error_new_password=error_new_password)

        # Ensure password was reentered for confirmation
        elif not request.form.get("confirmation"):
            error_reenter_password = "*Please reenter your password"
            return render_template("setting.html", error_reenter_password=error_reenter_password)

        # Ensure new password was confirmed correctly
        elif request.form.get("new_password") != request.form.get("confirmation"):
            error_password_match = "*Passwords do not match"
            return render_template("setting.html", error_password_match=error_password_match)

        elif request.form.get("new_password") == request.form.get("confirmation"):
            db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(
                request.form.get("new_password")), session["user_id"])
            return render_template("setting.html")

    # User reached route via GET
    else:
        return render_template("setting.html")

@app.route("/delete-account", methods=["GET", "POST"])
@login_required
def delete_account():

    # User submits form
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("delete-username"):
            error_username = "*Please type in your username"
            return render_template("setting.html", error_username=error_username)

        # Ensure password was submitted
        elif not request.form.get("delete-password"):
            error_password2 = "*Please type in your password"
            return render_template("setting.html", error_password2=error_password2)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("delete-username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("delete-password")):
            error_invalid = "*Invalid password / username"
            return render_template("setting.html", error_invalid=error_invalid)

        username = request.form.get("delete-username")

        # Delete user's posts
        db.execute("DELETE FROM posts WHERE username = ? AND user_id = ?", username, session["user_id"])

        # Delete user from database
        db.execute("DELETE FROM users WHERE id = ?", session["user_id"])

        # Clear user_id
        session.clear()

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("setting.html")
## END SETTINGS ##