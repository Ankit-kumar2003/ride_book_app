from flask import Flask, render_template, request, redirect, url_for, abort
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///rideapp.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

admin = Admin(app, name='RideExpress Admin', template_mode='bootstrap3')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    user_type = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class RideRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pickup = db.Column(db.String(200), nullable=False)
    dropoff = db.Column(db.String(200), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    user = db.relationship('User', backref=db.backref('ride_requests', lazy=True))

class AdminModelView(ModelView):
    def is_accessible(self):
        return True  # Admin is now accessible without authentication

admin.add_view(AdminModelView(User, db.session))
admin.add_view(AdminModelView(RideRequest, db.session))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route("/", endpoint="home")
def home():
    return render_template("home.html")

@app.route("/about", endpoint="about")
def about():
    return render_template("about.html")

@app.route("/book", methods=["GET", "POST"], endpoint="book_ride")
@login_required
def book_ride():
    error = None
    if request.method == "POST":
        pickup = request.form.get("pickup", "").strip()
        dropoff = request.form.get("dropoff", "").strip()
        date_str = request.form.get("date", "").strip()
        if not pickup or not dropoff or not date_str:
            error = "All fields are required."
        else:
            try:
                # Convert string to datetime object
                date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M')
                ride_request = RideRequest(
                    user_id=current_user.id,
                    pickup=pickup,
                    dropoff=dropoff,
                    date=date  # Pass the datetime object
                )
                db.session.add(ride_request)
                db.session.commit()
                return render_template(
                    "confirm.html", pickup=pickup, dropoff=dropoff, date=date_str
                )
            except ValueError:
                error = "Invalid date format. Please use the format YYYY-MM-DDTHH:MM."
    return render_template("book_ride.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        user_type = request.form.get("user_type", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        terms = request.form.get("terms")

        if not all(
            [
                full_name,
                email,
                phone,
                address,
                user_type,
                password,
                confirm_password,
                terms,
            ]
        ):
            error = "All fields are required."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif User.query.filter_by(email=email).first():
            error = "Email already registered."
        else:
            is_admin = email == "admin@rideexpress.com"
            user = User(
                full_name=full_name,
                email=email,
                phone=phone,
                address=address,
                user_type=user_type,
                password=password,
                is_admin=is_admin,
            )
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for("home"))
    return render_template("register.html", error=error)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            return redirect(url_for("home"))
        else:
            error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    users = User.query.all()
    ride_requests = RideRequest.query.all()
    return render_template("admin_dashboard.html", users=users, ride_requests=ride_requests)

if __name__ == "__main__":
    app.secret_key = "your_secret_key"  # Required for session management
    with app.app_context():
        db.create_all()
    app.run(debug=True)

