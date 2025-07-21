from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import current_user, login_required, AnonymousUserMixin
from token_utils import generate_confirmation_token, confirm_token
from werkzeug.security import generate_password_hash
from flask_login import login_required
from flask_login import UserMixin
from datetime import datetime
from flask import render_template
from flask_login import current_user, login_required
from flask import request, jsonify
from flask import Flask, render_template, request, jsonify
import requests
import threading
import time
from googlesearch import search
from flask_wtf import CSRFProtect
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = 'mybeiergroupportal2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['WTF_CSRF_ENABLED'] = False  # 🔥 disables CSRF checks

login_manager = LoginManager()
login_manager.login_view = 'login'  # Name of your login route
login_manager.init_app(app)
login_manager.login_message = "Please log in to access this page "




# Configuration for file uploads
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max file size
from flask_mail import Mail, Message

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'lindiwe02magwaza@gmail.com'
app.config['MAIL_PASSWORD'] = 'kwhvypgynndeqyyu'  # Not your Gmail password — see note below
mail = Mail(app)
def send_application_status_email(user, status):
    subject = f"Your Beier Group Application Status: {status}"
    if status == 'Accepted':
        body = f"Hi {user.first_name},\n\n🎉 Congratulations! Your application has been accepted! We’re excited to have you onboard."
    else:
        body = f"Hi {user.first_name},\n\n Unfortunately, your application was not successful this time. We wish you all the best."

    msg = Message(subject, sender='your_email@gmail.com', recipients=[user.email])
    msg.body = body
    mail.send(msg)

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


db = SQLAlchemy(app)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)  # e.g. Tech, Admin, etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'))
    status = db.Column(db.String(20), default='Pending')  # ⏳ Pending, ✅ Accepted, ❌ Rejected
    cv_viewed = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref='applications')
    job = db.relationship('Job', backref='applications')


login_manager = LoginManager(app)
login_manager.login_view = 'login'
# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    cv_filename = db.Column(db.String(255))
    first_name = db.Column(db.String(100))
    gender = db.Column(db.String(20))
    province = db.Column(db.String(100))
    country = db.Column(db.String(100))
    postal_code = db.Column(db.String(20))
    is_admin = db.Column(db.Boolean, default=False)
    is_confirmed = db.Column(db.Boolean, default=False)
    application_status = db.Column(db.String(20), default='Pending') 


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/welcome')
def welcome():
    return render_template('home.html')


@app.route('/')
def landing_page():
    return render_template('home.html')
 # your full homepage template with register/login links

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash("Passwords do not match ")
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists')
            return redirect(url_for('register'))

        # Create new user (not confirmed yet)
        new_user = User(email=email, password=hashed_pw, is_confirmed=False)
        db.session.add(new_user)
        db.session.commit()

        # ✅ Email verification
        token = generate_confirmation_token(email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        msg = Message('Confirm Your Email', sender='your_email@gmail.com', recipients=[email])
        msg.body = f'''Hi {email}! 👋

Please confirm your email by clicking the link below:
{confirm_url}

If you didn’t sign up, please ignore this message.

Thanks,
Lindiwe M '''

        mail.send(msg)

        flash('Account created 🎉 Please check your email to confirm your address.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('view_jobs'))  # <- changed here
        else:
            flash('Invalid email or password ')
        return redirect(url_for('login'))  # ✅


    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('welcome'))  # Or 'login' or any page that doesn't require job_id


import os
from werkzeug.utils import secure_filename

@app.route('/details/<int:job_id>', methods=['GET', 'POST'])
@login_required
def details(job_id):
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        gender = request.form.get('gender')
        country = request.form.get('country')
        province = request.form.get('province')
        postal_code = request.form.get('postal_code')
        cv_file = request.files.get('cv')

        # Save uploaded CV if it exists
        if cv_file:
            filename = secure_filename(cv_file.filename)
            upload_path = os.path.join('uploads', filename)
            cv_file.save(upload_path)

            # Update current user’s profile with new data
            current_user.first_name = first_name
            current_user.gender = gender
            current_user.country = country
            current_user.province = province
            current_user.postal_code = postal_code
            current_user.cv_filename = filename
            db.session.commit()
        else:
            flash("CV upload failed! Please try again.")

        # Check if the user already applied
        existing_application = Application.query.filter_by(
            user_id=current_user.id, job_id=job_id
        ).first()

        if existing_application:
            flash("You’ve already applied for this job ")
        else:
            new_app = Application(user_id=current_user.id, job_id=job_id)
            db.session.add(new_app)
            db.session.commit()
            flash("Application submitted successfully ")

        return redirect(url_for('profile'))

    return render_template('details.html', job_id=job_id, email=current_user.email)






from flask_login import login_required

@app.route('/profile')
@login_required
def profile():
    user_applications = Application.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', applications=user_applications)





from flask import send_from_directory

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash('Invalid or expired confirmation link. ')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()

    if user.is_confirmed:
        flash('Account already confirmed ✅ Please log in.')
    else:
        user.is_confirmed = True
        db.session.commit()
        flash('Email confirmed successfully  You can now log in.')

    return redirect(url_for('login'))
@app.route('/reset', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_confirmation_token(email)
            reset_url = url_for('reset_token', token=token, _external=True)
            msg = Message('Reset Your Password', sender='your_email@gmail.com', recipients=[email])
            msg.body = f'''Hi {email},

Click below to reset your password:
{reset_url}

If you didn't request this, just ignore it.
'''
            mail.send(msg)
            flash("Password reset link sent! 📧")
            return redirect(url_for('login'))
        else:
            flash("Email not found ")
            return redirect(url_for('reset_request'))

    return render_template('reset_request.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    email = confirm_token(token)
    if not email:
        flash("Invalid or expired link.")
        return redirect(url_for('reset_request'))

    user = User.query.filter_by(email=email).first_or_404()

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash("Passwords don’t match ")
            return redirect(request.url)

        user.password = generate_password_hash(password, method='pbkdf2:sha256')
        db.session.commit()
        flash("Password updated! ✅ Now log in.")
        return redirect(url_for('login'))

    return render_template('reset_form.html')

@app.route('/admin/update_application/<int:app_id>', methods=['POST'])
@login_required
def admin_update_application(app_id):
    if not current_user.is_admin:
        flash("Access denied  Admins only.")
        return redirect(url_for('profile'))

    application = Application.query.get_or_404(app_id)
    action = request.form.get('action')

    if action == 'viewed':
        application.cv_viewed = True
        flash('👀 CV marked as viewed')
    elif action == 'accept':
        application.status = 'Accepted'
        send_application_status_email(application.user, 'Accepted')
        flash('✅ Application accepted')
    elif action == 'reject':
        application.status = 'Rejected'
        send_application_status_email(application.user, 'Rejected')
        flash('❌ Application rejected')

    db.session.commit()
    return redirect(url_for('admin'))



@app.route('/reject/<int:user_id>')
@login_required
def reject_application(user_id):
    if not current_user.is_admin:
        flash("Access denied  Admins only.")
        return redirect(url_for('profile'))

    user = User.query.get_or_404(user_id)
    user.application_status = 'Rejected'
    db.session.commit()
    send_application_status_email(user, 'Rejected')
    flash(f"❌ {user.email} has been rejected.")
    return redirect(url_for('admin'))

def create_jobs():
    if Job.query.count() == 0:
        jobs = [
            Job(title="Frontend Developer", description="Build user interfaces using HTML, CSS, and JavaScript.", category="Tech"),
            Job(title="Backend Developer", description="Design server-side logic and APIs.", category="Tech"),
            Job(title="Full Stack Developer", description="Work on both frontend and backend.", category="Tech"),
            Job(title="Data Scientist", description="Analyze data and build predictive models.", category="Tech"),
            Job(title="DevOps Engineer", description="Manage CI/CD pipelines and infrastructure.", category="Tech"),
        ]
        db.session.add_all(jobs)
        db.session.commit()
        print("✅ Jobs seeded into the database.")




@app.route('/apply/<int:job_id>', methods=['POST'])
@login_required
def apply_job(job_id):
    if not current_user.cv_filename:
        return redirect(url_for('details', job_id=job_id))  # ✅ pass job_id here


    job = Job.query.get_or_404(job_id)
    existing_app = Application.query.filter_by(user_id=current_user.id, job_id=job_id).first()

    if existing_app:
        flash("You’ve already applied for this job ")
    else:
       application = Application(user_id=current_user.id, job_id=job_id)
       db.session.add(application)
       db.session.commit()


    return redirect(url_for('details', job_id=job_id))


@login_manager.unauthorized_handler
def unauthorized():
    flash("You need to log in to access this page!")
    return redirect(url_for('login'))


@app.route('/my_applications')
@login_required
def my_applications():
    apps = Application.query.filter_by(user_id=current_user.id).all()
    return render_template('my_applications.html', apps=apps)

from flask_login import current_user, login_required

@app.route('/jobs')
@login_required
def view_jobs():
    all_jobs = Job.query.all()
    # If user logged in, get their applications for UI logic
    if current_user.is_authenticated:
        user_apps = [app.job_id for app in Application.query.filter_by(user_id=current_user.id).all()]
    else:
        user_apps = []
    return render_template('jobs.html', jobs=all_jobs, user_applications=user_apps)



@app.route('/job/<int:job_id>', methods=['GET', 'POST'])
@login_required
def job_detail(job_id):
    job = Job.query.get_or_404(job_id)

    # Check if already applied
    existing_app = Application.query.filter_by(user_id=current_user.id, job_id=job_id).first()

    if request.method == 'POST':
        if existing_app:
            flash('You already applied for this job ')
        else:
            new_app = Application(user_id=current_user.id, job_id=job_id, status='Pending')
            db.session.add(new_app)
            db.session.commit()
            flash('Application submitted! ')
        return redirect(url_for('profile'))

    return render_template('job_detail.html', job=job, existing_app=existing_app)



@app.route('/seed_jobs')
def seed_jobs():
    existing = Job.query.first()
    if existing:
        return "Jobs already added! "

    jobs = [
        Job(title="Junior Software Developer", description="Work on backend APIs and fix bugs.", category="Tech"),
        Job(title="Front-End Developer", description="Design UI using HTML/CSS/JS.", category="Tech"),
        Job(title="Data Scientist Intern", description="Analyze data trends for business decisions.", category="Tech"),
        Job(title="Mobile App Developer", description="Build Android and iOS apps using Flutter.", category="Tech"),
        Job(title="Cybersecurity Analyst", description="Monitor and secure company systems.", category="Tech"),
    ]
    db.session.add_all(jobs)
    db.session.commit()
    return "✅ 5 Tech Jobs added!"

from googlesearch import search  # 👈 Add this at the top of your file

from flask import Flask, request, jsonify
import re

@app.route('/chatbot', methods=['POST'])
def chatbot():
    data = request.get_json()
    user_message = data.get('message', '').lower()

    if re.search(r"\b(location|where.*(located|find))\b", user_message):
        return jsonify(reply="We're located at 40 Gillitts Road, Pinetown, Durban, KwaZulu-Natal, South Africa.")
    elif re.search(r"\b(ceo|who.*(ceo|lead|boss))\b", user_message):
        return jsonify(reply="The CEO of Beier Group is Warren Sachs, appointed in July 20242. He’s a seasoned executive with nearly 30 years of experience in manufacturing and holds an MBA with distinction from the Gordon Institute of Business Science.")
    elif re.search(r"\b(history|when.*founded|how.*start)\b", user_message):
        return jsonify(reply="Beier Group was founded in 1929 and has grown into a diversified manufacturing company with operations in medical, filtration, and industrial textiles.")
    elif re.search(r"\b(job|available|vacancy|career|work)\b", user_message):
        return jsonify(reply="Check our Jobs page for the latest openings 💼.")
    else:
        return jsonify(reply="Hmm... I’m not sure, but I found something that might help: https://www.beier.co.za/contact/ 🔍")



import os
from werkzeug.utils import secure_filename

@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        # Update user fields
        current_user.first_name = request.form.get('first_name')
        current_user.gender = request.form.get('gender')
        current_user.country = request.form.get('country')
        current_user.province = request.form.get('province')
        current_user.postal_code = request.form.get('postal_code')

        # Handle CV upload
        if 'cv' in request.files:
            file = request.files['cv']
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                current_user.cv_filename = filename

        db.session.commit()
        flash('✅ Your profile has been updated successfully!')
        return redirect(url_for('profile'))

    return render_template('update_profile.html', user=current_user)


@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash("Access denied 🛑 Admins only.")
        return redirect(url_for('profile'))

    applications = Application.query.all()

    return render_template('admin.html', applications=applications)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_jobs()  # 👈 This will only run once and only if the DB is empty
    app.run(host='0.0.0.0', debug=True)



