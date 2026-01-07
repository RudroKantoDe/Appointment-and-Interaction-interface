from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ---------- Database Models ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # doctor or patient
    phone = db.Column(db.String(20))

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_name = db.Column(db.String(100), nullable=False)
    doctor_name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    description = db.Column(db.String(200))
    status = db.Column(db.String(20), default='Pending')  # Pending / Approved / Rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointment.id'))
    sender = db.Column(db.String(50))   # 'doctor' or 'patient'
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ---------- Routes ----------
@app.route('/')
def home():
    return render_template('index.html')

# ---------- Register ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        role = request.form['role']
        phone = request.form.get('phone', '')

        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))

        new_user = User(username=username, password=password, role=role, phone=phone)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

# ---------- Login ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Login successful!')

            if user.role == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            else:
                return redirect(url_for('patient_dashboard'))
        else:
            flash('Invalid username or password!')
    return render_template('login.html')

# ---------- Logout ----------
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

# ---------- Patient Dashboard ----------
@app.route('/patient', methods=['GET', 'POST'])
def patient_dashboard():
    if 'user_id' not in session or session['role'] != 'patient':
        flash('Access denied!')
        return redirect(url_for('login'))

    if request.method == 'POST':
        doctor_name = request.form['doctor_name']
        date = request.form['date']
        description = request.form['description']

        if not doctor_name or not date or not description:
            flash('All fields are required!')
            return redirect(url_for('patient_dashboard'))

        new_appointment = Appointment(
            patient_name=session['username'],
            doctor_name=doctor_name,
            date=date,
            description=description,
            status='Pending'
        )
        db.session.add(new_appointment)
        db.session.commit()
        flash('Appointment request sent successfully!')

    doctors = User.query.filter_by(role='doctor').all()
    appointments = Appointment.query.filter_by(patient_name=session['username']).all()
    return render_template('patient_dashboard.html', doctors=doctors, appointments=appointments)

# ---------- Doctor Dashboard ----------
@app.route('/doctor', methods=['GET', 'POST'])
def doctor_dashboard():
    if 'user_id' not in session or session['role'] != 'doctor':
        flash('Access denied!')
        return redirect(url_for('login'))

    if request.method == 'POST':
        appointment_id = request.form.get('appointment_id')
        action = request.form.get('action')

        appointment = Appointment.query.get(appointment_id)
        if appointment:
            if action == 'approve':
                appointment.status = 'Approved'
            elif action == 'reject':
                appointment.status = 'Rejected'
            db.session.commit()
            flash(f'Appointment {action}ed successfully!')

    appointments = Appointment.query.filter_by(doctor_name=session['username']).all()
    return render_template('doctor_dashboard.html', appointments=appointments)

# ---------- Chat Route ----------
@app.route('/chat/<int:appointment_id>', methods=['GET', 'POST'])
def chat(appointment_id):
    # Ensure the user is logged in
    if 'user_id' not in session:
        flash("Please log in first!")
        return redirect(url_for('login'))

    # Get appointment
    appointment = Appointment.query.get_or_404(appointment_id)

    # Only allow doctor or patient involved in this appointment
    if session['username'] not in [appointment.patient_name, appointment.doctor_name]:
        flash("Access denied.")
        return redirect(url_for('home'))

    # Handle new message
    if request.method == 'POST':
        message_content = request.form['message']
        if message_content.strip():  # ignore empty messages
            message = Message(
                appointment_id=appointment_id,
                sender=session['role'],
                content=message_content
            )
            db.session.add(message)
            db.session.commit()

    # Get all messages for this appointment
    messages = Message.query.filter_by(appointment_id=appointment_id).order_by(Message.timestamp.asc()).all()

    return render_template('chat.html', messages=messages, appointment=appointment)


# ---------- Run ----------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
