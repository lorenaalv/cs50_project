import os
import re
import requests

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, url_for, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
# app = Flask(__name__)
app = Flask(__name__, template_folder="templates")

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///purchases.db")

# Creates table to track purchases
db.execute(
    """
        CREATE TABLE IF NOT EXISTS purchases (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            item TEXT NOT NULL,
            location INTEGER NOT NULL,
            price REAL NOT NULL,
            timestamp DATETIME DEFAULT
        CURRENT_TIMESTAMP)
               """
)

# Creates tables to keep track of users
db.execute(
    """
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    hash TEXT NOT NULL)
    """
)

@app.route("/log_purchase", methods=["GET", "POST"])
@login_required
def log_purchase():
    # Handles logging a purchase
    if request.method == "POST":
        user_id = session["user_id"]
        item = request.form.get("item")
        location = request.form.get("location")
        price = request.form.get("price")

        print(f"Form Data - Item: {item}, Location: {location}, Price: {price}")
# Validate form data
        if not item or not location or not price:
            print("Validation Error: Missing field(s)")
            return apology("All fields are required", 400)

        if not re.match("^[A-Za-z ]+$", item):
            print("Validation Error: Item format")
            return apology("Item must contain only letters", 400)

        if not re.match("^[A-Za-z ]+$", location):
            print("Validation Error: Location format")
            return apology("Location must contain only letters", 400)

        try:
            price = float(price)
            if price < 0:
                raise ValueError
        except ValueError:
            print("Validation Error: Price format")
            return apology("Price must be a positive number", 400)

# Use Google Maps API for geocoding and getting lat lng coordinates for the map
        GOOGLE_MAPS_API_KEY = "AIzaSyAw6k0C6dfwFNSTgGlvYIcygXe3sDyHCa4"
        geocoding_url = f"https://maps.googleapis.com/maps/api/geocode/json"
        params = {
            "address": location,
            "key": GOOGLE_MAPS_API_KEY
        }
        response = requests.get(geocoding_url, params=params)
        geocoding_data = response.json()
        print(f"Complete Geocoding response: {geocoding_data}")

# Check whether geocoding was successful
        if geocoding_data["status"] == "OK" and geocoding_data["results"]:
            lat = geocoding_data["results"][0]["geometry"]["location"]["lat"]
            lng = geocoding_data["results"][0]["geometry"]["location"]["lng"]
            print(f"Geocoded Lat: {lat}, Lng: {lng}")
        else:
            print("Geocoding failed")
            return apology("Geocoding failed or invalid location")

# Insert purchases into database
        db.execute("INSERT INTO purchases (user_id, item, location, price, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?)",
                   user_id, item, location, price, lat, lng)

        print("Purchase logged successfully")
        return redirect("/view_purchases")
    else:
        return render_template("log_purchase.html")

@app.route("/view_purchases")
@login_required
def view_purchases():
    user_id = session["user_id"]
    purchases = db.execute("SELECT * FROM purchases WHERE user_id = ?", user_id)
    return render_template("view_purchases.html", purchases=purchases)

@app.route("/map")
@login_required
def map():
    user_id = session["user_id"]
    purchases = db.execute("Select * FROM purchases WHERE user_id = ?", user_id)
    # Your code to gather data for the map and render the map template
    return render_template("map.html", purchases=purchases)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("change_password.html")
    else:
        # Get form data
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Fetch the hashed password from the database
        hashed_password = db.execute(
            "SELECT hash FROM users WHERE id = :user_id", user_id=session["user_id"]
        )[0]["hash"]

        # Check if current password is correct
        if not check_password_hash(hashed_password, current_password):
            return apology("Your current password is incorrect.")

        # Check if new password and confirmation match
        if new_password != confirm_password:
            return apology(
                "Your new password and your confirmation password are not correct."
            )

        # Has the new password
        hashed_new_password = generate_password_hash(new_password)

        # Update the password in database
        db.execute(
            "UPDATE users SET hash = :new_hash WHERE id = :user_id",
            new_hash=hashed_new_password,
            user_id=session["user_id"],
        )

        return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            return apology("Username is required")

        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not password:
            return apology("Password is required")
        if password != confirmation:
            return apology("Passwords do not match")
        # Check if username is already taken
        result = db.execute(
            "SELECT * FROM users WHERE username = :username", username=username
        )
        if result:
            return apology("Username taken.")
        else:
            hashed_password = generate_password_hash(password)
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)",
                username,
                hashed_password,
            )
        return redirect("/")
    else:
        return render_template("register.html")

@app.route("/delete_purchase/<int:purchase_id>", methods=["GET"])
@login_required
def delete_purchase(purchase_id):
    # Gets the user ID from current session
    user_id = session["user_id"]
    # Query database to check if purchase matching the ID belongs to logged in user
    purchase = db.execute("SELECT * FROM purchases WHERE id = ? AND user_id = ?", purchase_id, user_id)
#    Check if purchase exists and belongs to the user
    if purchase:
        # Purchase exists and belongs to user then delete from database
        db.execute("DELETE FROM purchases WHERE id = ?", purchase_id)
        print("Purchase deleted successfully")
    else:
        # Purchase doesn't exist or doesn't belong to user then send apology message
        print("Purchase not found or does not belong to the user")
    return redirect(url_for('view_purchases'))

@app.route("/")
@login_required
def index():
    return render_template("index.html")
