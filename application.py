import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get stocks owned, plus shares of that stock
    stocks = db.execute("SELECT stock, shares FROM shares WHERE user_id = ?", session.get("user_id"))

    # Get current cash value
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session.get("user_id"))

    # Get cash + value of shares
    total = 0
    for stock in range(len(stocks)):
        symbol = stocks[stock]["stock"]
        info = lookup(symbol)
        value = info["price"] * stocks[stock]["shares"]
        total += value
    balance = total + cash[0]["cash"]

    return render_template("index.html", balance=balance, cash=cash, stocks=stocks, lookup=lookup)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        # Check if stock exists
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        stock = lookup(symbol)

        if stock == None:
            return apology("No Such Stock Exists")
        # Check if shares fractional
        elif "." in shares:
            return apology("Cannot purchase fractional shares")
        # Check if input isn't a number
        elif shares.isnumeric() == False:
            return apology("Invalid Input")
        # Check if shares positive
        elif int(shares) < 0:
            return apology("Must Input Positive Number")
        else:
            # Check how much cash user has
            cash = db.execute("SELECT cash FROM users WHERE id = ?", session.get("user_id"))

            # Check total cost of shares
            cost = stock["price"] * int(shares)

            # Check if they have enough to purchase
            if cost < cash[0]["cash"] or cost == cash[0]["cash"]:
                balance = cash[0]["cash"] - cost
                # Deduct cost of shares from user's cash
                db.execute("UPDATE users SET cash = ? WHERE id = ?",
                           balance, session.get("user_id"))
                # Add to transactions table
                db.execute("INSERT INTO transactions (user_id, stock, shares, price, type, time) VALUES ((SELECT id FROM users WHERE id = ?), ?, ?, ?, ?, CURRENT_TIMESTAMP)", session.get("user_id"), stock["symbol"], shares, stock["price"], "BUY")

                # Check if shares in stock not already owned
                rows = db.execute("SELECT stock FROM shares WHERE user_id = ? AND stock = ?",
                                  session.get("user_id"), stock["symbol"])

                if len(rows) != 1:
                    db.execute("INSERT INTO shares (user_id, stock, shares) VALUES ((SELECT id from users WHERE id = ?), ?, ?)",
                               session.get("user_id"), stock["symbol"], shares)

                else:
                    # Add newly bought shares to existing shares
                    existing = db.execute("SELECT shares FROM shares WHERE user_id = ? AND stock = ?",
                                          session.get("user_id"), stock["symbol"])

                    total = (existing[0]["shares"]) + int(shares)

                    db.execute("UPDATE shares SET shares = ? WHERE user_id = ? and stock = ?",
                               total, session.get("user_id"), stock["symbol"])

                # Send user to index page
                return redirect("/")
            else:
                return apology("You do not have enough in your account for this purchase")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Retrieve all info from transactions table
    transactions = db.execute("SELECT stock, shares, price, type, time FROM transactions WHERE user_id = ?", session.get("user_id"))

    return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # Display quoted template if user has typed in symbol
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # Run lookup to find stock info
        STOCKINFO = lookup(symbol)

        # If entry was invalid return error
        if STOCKINFO == None:
            return apology("No Such Stock Exists")
        # Otherwise show quote
        else:
            return render_template("quoted.html", stock=STOCKINFO)
    # Display template to retrieve quote all other circumstances
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check if username, password, or confirmation blank
        if not username or not password or not confirmation:
            return apology("Fields Cannot Be Left Blank")

        # Check if username taken
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) == 1:
            return apology("Username Already Taken")

        # Check if passwords match
        if password != confirmation:
            return apology("Passwords Do Not Match")

        # Insert new user into users table, storing hash of user's password
        hash_pass = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash_pass)
        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":

        # Get submitted info
        stock = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # Check if fields are empty
        if not stock or not shares:
            return apology("Fields Cannot Be Left Blank")

        # Check if user doesn't have shares for stock
        rows = db.execute("SELECT shares FROM shares WHERE user_id = ? AND stock = ?", session.get("user_id"), stock)

        if len(rows) == 0:
            return apology("You do not own shares of this stock")

        # Check if the num shares they try to sell is not positive or more than they own

        if rows[0]["shares"] < shares or shares < 0:
            return apology("You do not have enough shares to complete the sale")

        # If all checks were passed, update records

        # Calculate how much they earn from sale
        info = lookup(stock)
        price = info["price"]
        sale = price * shares

        # Add sale price to their account balance

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session.get("user_id"))

        balance = sale + cash[0]["cash"]

        db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session.get("user_id"))

        # Subtract stocks from shares table, add transaction to transactions table
        remaining = (rows[0]["shares"]) - shares

        db.execute("INSERT INTO transactions (user_id, stock, shares, price, type, time) VALUES ((SELECT id FROM users WHERE id = ?), ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                   session.get("user_id"), info["symbol"], shares, info["price"], "SELL")
        db.execute("UPDATE shares SET shares = ? WHERE user_id = ? AND stock = ?",
                   remaining, session.get("user_id"), info["symbol"])

        return redirect("/")

    else:
        # Retrieve owned stocks and shares
        stocks = db.execute("SELECT stock, shares FROM shares WHERE user_id = ?", session.get("user_id"))

        return render_template("sell.html", stocks=stocks)


@app.route("/fund", methods=["GET", "POST"])
@login_required
def fund():
    """Add funds to cash balance"""

    if request.method == "POST":
        # Retrieve amount added from form
        amount = float(request.form.get("amount"))

        # Retrieve current cash balance
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session.get("user_id"))

        # Add new funds to existing balance
        funds = amount + cash[0]["cash"]

        # Update cash balance in table
        db.execute("UPDATE users SET cash = ? WHERE id = ?", funds, session.get("user_id"))

        return redirect("/")

    else:
        return render_template("fund.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
