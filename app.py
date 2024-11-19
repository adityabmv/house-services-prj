from flask import Flask, render_template
import sqlite3

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)

# Configure the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///household_services.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class Admin(db.Model):
    admin_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(100), nullable=False)


class Customer(db.Model):
    customer_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    pin_code = db.Column(db.String(10), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(10), default='active')  # active/blocked


class ServiceProfessional(db.Model):
    professional_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    pin_code = db.Column(db.String(10), nullable=False)
    service_type = db.Column(db.String(50), nullable=False)
    experience = db.Column(db.String(100))
    description = db.Column(db.Text)
    profile_docs = db.Column(db.String(200))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(10), default='pending')  # approved/pending/blocked
    rating = db.Column(db.Float, default=0.0)


class Service(db.Model):
    service_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    base_price = db.Column(db.Float, nullable=False)
    time_required = db.Column(db.String(50))
    description = db.Column(db.Text)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(10), default='active')  # active/inactive


class ServiceRequest(db.Model):
    request_id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.service_id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.customer_id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('service_professional.professional_id'), nullable=True)
    date_of_request = db.Column(db.DateTime, default=datetime.utcnow)
    preferred_date = db.Column(db.DateTime)
    date_of_completion = db.Column(db.DateTime)
    service_status = db.Column(db.String(10), default='requested')  # requested/assigned/closed
    remarks = db.Column(db.Text)
    address = db.Column(db.String(200), nullable=False)
    pin_code = db.Column(db.String(10), nullable=False)


class Review(db.Model):
    review_id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('service_request.request_id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.customer_id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('service_professional.professional_id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1 to 5 stars
    comments = db.Column(db.Text)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)




@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/register/customer', methods=['GET'])
def register_customer():
    return render_template('customer/register.html')

# API Endpoints

# Sample Route: Add a customer
@app.route('/customers', methods=['POST'])
def add_customer():
    data = request.json
    customer = Customer(
        name=data['name'],
        email=data['email'],
        password=data['password'],
        phone_number=data['phone_number'],
        address=data['address'],
        pin_code=data['pin_code']
    )
    db.session.add(customer)
    db.session.commit()
    return jsonify({"message": "Customer added successfully", "customer_id": customer.customer_id})


# Sample Route: Add a service professional
@app.route('/professionals', methods=['POST'])
def add_professional():
    data = request.json
    professional = ServiceProfessional(
        name=data['name'],
        email=data['email'],
        password=data['password'],
        phone_number=data['phone_number'],
        address=data['address'],
        pin_code=data['pin_code'],
        service_type=data['service_type'],
        experience=data['experience'],
        description=data['description'],
        profile_docs=data['profile_docs']
    )
    db.session.add(professional)
    db.session.commit()
    return jsonify({"message": "Service Professional added successfully", "professional_id": professional.professional_id})


# Sample Route: Add a service
@app.route('/services', methods=['POST'])
def add_service():
    data = request.json
    service = Service(
        name=data['name'],
        base_price=data['base_price'],
        time_required=data['time_required'],
        description=data['description']
    )
    db.session.add(service)
    db.session.commit()
    return jsonify({"message": "Service added successfully", "service_id": service.service_id})


# Sample Route: Create a service request
@app.route('/service-requests', methods=['POST'])
def add_service_request():
    data = request.json
    service_request = ServiceRequest(
        service_id=data['service_id'],
        customer_id=data['customer_id'],
        professional_id=data.get('professional_id'),  # Nullable
        preferred_date=datetime.strptime(data['preferred_date'], '%Y-%m-%d') if 'preferred_date' in data else None,
        remarks=data.get('remarks', ''),
        address=data['address'],
        pin_code=data['pin_code']
    )
    db.session.add(service_request)
    db.session.commit()
    return jsonify({"message": "Service Request created successfully", "request_id": service_request.request_id})


# Sample Route: Add a review
@app.route('/reviews', methods=['POST'])
def add_review():
    data = request.json
    review = Review(
        request_id=data['request_id'],
        customer_id=data['customer_id'],
        professional_id=data['professional_id'],
        rating=data['rating'],
        comments=data.get('comments', '')
    )
    db.session.add(review)
    db.session.commit()
    return jsonify({"message": "Review added successfully", "review_id": review.review_id})




import hashlib

def hash_password(password):
    """Hashes the password for storage."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_password, provided_password):
    """Verifies a hashed password."""
    return stored_password == hashlib.sha256(provided_password.encode()).hexdigest()


@app.route('/login', methods=['POST'])
def login_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')  # 'customer' or 'professional'

    if not email or not password or not role:
        return jsonify({"error": "Email, password, and role are required"}), 400

    if role == 'customer':
        user = Customer.query.filter_by(email=email).first()
    elif role == 'professional':
        user = ServiceProfessional.query.filter_by(email=email).first()
    else:
        return jsonify({"error": "Invalid role specified"}), 400

    if user and verify_password(user.password, password):
        if user.status in ('blocked', 'pending'):
            return jsonify({"error": f"Account is {user.status}. Contact support."}), 403
        return jsonify({"message": "Login successful", "user_id": user.customer_id if role == 'customer' else user.professional_id, "role": role}), 200
    else:
        return jsonify({"error": "Invalid email or password"}), 401


if __name__ == '__main__':
    with app.app_context():
        # print("Creating tables...")
        db.create_all()  # This should create all tables
        # print("Tables created successfully.")
    app.run(debug=True)

