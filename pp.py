from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import current_user, login_required, AnonymousUserMixin
from token_utils import generate_confirmation_token, confirm_token
from werkzeug.security import generate_password_hash
from flask_login import login_required
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'


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
        body = f"Hi {user.first_name},\n\n😔 Unfortunately, your application was not successful this time. We wish you all the best."

    msg = Message(subject, sender='your_email@gmail.com', recipients=[user.email])
    msg.body = body
    mail.send(msg)

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


db = SQLAlchemy(app)
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
            flash("Passwords do not match 😵‍💫")
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists 😥')
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
Your Flask App 🙌'''

        mail.send(msg)

        flash('Account created 🎉 Please check your email to confirm your address.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # 👇 Debugging info to see what’s going on in terminal
        print("Login attempt:", email, password)

        user = User.query.filter_by(email=email).first()
        print("User found:", user is not None)

        if user:
            print("Password correct:", check_password_hash(user.password, password))
            print("Is admin:", user.is_admin)

        # ✅ Secure authentication check with admin redirect
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('details'))
        else:
            flash('Invalid email or password 😵')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('details'))

@app.route('/details', methods=['GET', 'POST'])
@login_required
def details():
    # 🛑 Skip form if details already submitted
    if current_user.cv_filename:
        flash("You've already submitted your details. 🚀")
        return redirect(url_for('profile'))

    if request.method == 'POST':
        current_user.first_name = request.form['first_name']
        current_user.gender = request.form['gender']
        current_user.province = request.form['province']
        current_user.country = request.form['country']
        current_user.postal_code = request.form['postal_code']

        file = request.files['cv']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.cv_filename = filename

        db.session.commit()
        flash("Details saved! 🎉")
        return redirect(url_for('profile'))

    return render_template('details.html', email=current_user.email)


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

from flask import send_from_directory

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin')
@login_required
def admin():
    if isinstance(current_user, AnonymousUserMixin) or not getattr(current_user, 'is_admin', False):
        flash("Access denied 🛑 Admins only.")
        return redirect(url_for('profile'))

    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/make_admin/<int:user_id>')
@login_required
def make_admin(user_id):
    # Only allow if current user is already admin (extra safety)
    if not current_user.is_admin:
        flash("Access denied 🛑 Admins only.")
        return redirect(url_for('profile'))

    user = User.query.get(user_id)
    if not user:
        flash("User not found 😕")
        return redirect(url_for('admin'))

    user.is_admin = True
    db.session.commit()
    flash(f"{user.email} is now an admin! 🎉")
    return redirect(url_for('admin'))

@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash('Invalid or expired confirmation link. 😵‍💫')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()

    if user.is_confirmed:
        flash('Account already confirmed ✅ Please log in.')
    else:
        user.is_confirmed = True
        db.session.commit()
        flash('Email confirmed successfully 🎉 You can now log in.')

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
            flash("Email not found 😬")
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
            flash("Passwords don’t match 😵")
            return redirect(request.url)

        user.password = generate_password_hash(password, method='pbkdf2:sha256')
        db.session.commit()
        flash("Password updated! ✅ Now log in.")
        return redirect(url_for('login'))

    return render_template('reset_form.html')

@app.route('/accept/<int:user_id>')
@login_required
def accept_application(user_id):
    if not current_user.is_admin:
        flash("Access denied 🛑 Admins only.")
        return redirect(url_for('profile'))

    user = User.query.get_or_404(user_id)
    user.application_status = 'Accepted'
    db.session.commit()
    send_application_status_email(user, 'Accepted')
    flash(f"✅ {user.email} has been accepted.")
    return redirect(url_for('admin'))


@app.route('/reject/<int:user_id>')
@login_required
def reject_application(user_id):
    if not current_user.is_admin:
        flash("Access denied 🛑 Admins only.")
        return redirect(url_for('profile'))

    user = User.query.get_or_404(user_id)
    user.application_status = 'Rejected'
    db.session.commit()
    send_application_status_email(user, 'Rejected')
    flash(f"❌ {user.email} has been rejected.")
    return redirect(url_for('admin'))




if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # ✅ This recreates tables with new columns
        print("✅ Recreated database with updated schema.")
    app.run(host='0.0.0.0', debug=True)

