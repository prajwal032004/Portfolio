from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import io
import csv
import shutil
from sqlalchemy import or_

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure random key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)

# Database Models
class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    attachment_path = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    welcome_message = db.Column(db.Text)
    dark_mode = db.Column(db.Boolean, default=True)
    profile_picture = db.Column(db.String(200), default='default_profile.png')

class TempAdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Theme(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    primary_color = db.Column(db.String(7), default='#0ea5e9')
    secondary_color = db.Column(db.String(7), default='#0284c7')
    active = db.Column(db.Boolean, default=False)

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_path = db.Column(db.String(200), nullable=False)  # Can be a local path or URL
    icon_url = db.Column(db.String(200))
    verify_url = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    gif_url = db.Column(db.String(200), nullable=False)
    link_url = db.Column(db.String(200))
    online_url = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.relationship('Category', backref='projects')

class GitHubProject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    avatar_url = db.Column(db.String(200), default='https://github.com/prajwal032004/prajwal032004/blob/main/pngwing.com.png?raw=true')
    github_url = db.Column(db.String(200), nullable=False)
    online_url = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Database Initialization
def init_db():
    with app.app_context():
        db.create_all()
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admin'")
        if cursor.fetchone():
            cursor.execute("PRAGMA table_info(admin)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'welcome_message' not in columns:
                cursor.execute('ALTER TABLE admin ADD COLUMN welcome_message TEXT')
                cursor.execute("UPDATE admin SET welcome_message = 'Welcome to my portfolio!' WHERE welcome_message IS NULL")
            if 'dark_mode' not in columns:
                cursor.execute('ALTER TABLE admin ADD COLUMN dark_mode INTEGER DEFAULT 1')
            if 'profile_picture' not in columns:
                cursor.execute('ALTER TABLE admin ADD COLUMN profile_picture VARCHAR(200) DEFAULT \"default_profile.png\"')
        
        for table in ['temp_admin_user', 'action_log', 'notification', 'theme', 'certificate', 'category', 'project', 'git_hub_project']:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
            if not cursor.fetchone():
                db.create_all()

        conn.commit()
        conn.close()

        if not Admin.query.first():
            default_admin = Admin(
                username='prajwal',
                password_hash=generate_password_hash('prajwal1518'),
                welcome_message='Welcome to my portfolio!',
                dark_mode=True,
                profile_picture='default_profile.png'
            )
            db.session.add(default_admin)
            db.session.commit()

        if not Theme.query.first():
            default_theme = Theme(
                name='Default',
                primary_color='#0ea5e9',
                secondary_color='#0284c7',
                active=True
            )
            db.session.add(default_theme)
            db.session.commit()

        if not Category.query.first():
            default_categories = ['flask-python', 'nx cad', 'solidworks', 'catia v5']
            for cat_name in default_categories:
                if not Category.query.filter_by(name=cat_name).first():
                    category = Category(name=cat_name)
                    db.session.add(category)
            db.session.commit()

        if not GitHubProject.query.first():
            default_projects = [
                {
                    'title': 'Recipe Finder App',
                    'description': 'This Flask-based web application allows users to search for recipes using the Spoonacular API.',
                    'github_url': 'https://github.com/prajwal032004/Recipe-Maker.git'
                },
                {
                    'title': 'Simple-PDF-Merger',
                    'description': 'This Flask-based Python script merges multiple PDF files into a single PDF file.',
                    'github_url': 'https://github.com/prajwal032004/Simple-PDF-Merger.git',
                    'online_url': 'https://prajwalpdf.pythonanywhere.com/'
                },
                {
                    'title': 'Image Filter Web Application',
                    'description': 'This Flask-based web application allows users to apply filters to images.',
                    'github_url': 'https://github.com/prajwal032004/Flask-Image-Processing-Application.git'
                },
                {
                    'title': 'BalanceBuddy BMI Calculator',
                    'description': 'This Flask-based web application calculates the Body Mass Index (BMI) of users.',
                    'github_url': 'https://github.com/prajwal032004/BalanceBuddy.git'
                },
                {
                    'title': 'Secure Drop-a-File',
                    'description': 'A secure and user-friendly web application built with Flask for file sharing.',
                    'github_url': 'https://github.com/prajwal032004/Drop-a-File.git',
                    'online_url': 'https://prajwalab.pythonanywhere.com/'
                }
            ]
            for project in default_projects:
                if not GitHubProject.query.filter_by(title=project['title']).first():
                    new_project = GitHubProject(
                        title=project['title'],
                        description=project['description'],
                        github_url=project['github_url'],
                        online_url=project.get('online_url', '')
                    )
                    db.session.add(new_project)
            db.session.commit()

init_db()

# Decorators
def full_admin_required(f):
    def wrap(*args, **kwargs):
        if not session.get('admin_logged_in') or session.get('is_temp_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def login_required(f):
    def wrap(*args, **kwargs):
        if not (session.get('admin_logged_in') or session.get('temp_admin_logged_in')):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# Routes
@app.route('/')
def index():
    admin = Admin.query.first()
    notifications = Notification.query.filter_by(active=True).all()
    certificates = Certificate.query.order_by(Certificate.created_at.desc()).all()
    projects = Project.query.order_by(Project.created_at.desc()).all()
    categories = Category.query.all()
    github_projects = GitHubProject.query.order_by(GitHubProject.created_at.desc()).all()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('port.html', welcome_message=admin.welcome_message if admin else 'Welcome!', 
                         profile_picture=admin.profile_picture if admin else 'default_profile.png', 
                         notifications=notifications, certificates=certificates, projects=projects, 
                         categories=categories, github_projects=github_projects, active_theme=active_theme)

@app.route('/cv')
def cv():
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('cv.html', active_theme=active_theme)

@app.route('/submit_contact', methods=['POST'])
def submit_contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        
        attachment_path = None
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file and file.filename:
                try:
                    filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    attachment_path = filename
                except Exception as e:
                    flash(f'Failed to upload attachment: {str(e)}')
                    return redirect(url_for('index') + '#contact')

        new_message = ContactMessage(
            name=name,
            email=email,
            message=message,
            attachment_path=attachment_path
        )
        
        try:
            db.session.add(new_message)
            if session.get('admin_logged_in') and not session.get('is_temp_admin'):
                admin = Admin.query.filter_by(username=session.get('admin_username', 'prajwal')).first()
                if admin:
                    log = ActionLog(admin_id=admin.id, action=f"New contact message from {name}")
                    db.session.add(log)
            db.session.commit()
            flash('Message sent successfully!')
        except Exception as e:
            db.session.rollback()
            flash(f'Failed to save message: {str(e)}')
        
        return redirect(url_for('index') + '#contact')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        admin = Admin.query.filter_by(username=username).first()
        temp_admin = TempAdminUser.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password_hash, password):
            session['admin_logged_in'] = True
            session['admin_username'] = admin.username
            session['dark_mode'] = admin.dark_mode
            session['is_temp_admin'] = False
            log = ActionLog(admin_id=admin.id, action="Logged in")
            db.session.add(log)
            db.session.commit()
            return redirect(url_for('admin_dashboard'))
        elif temp_admin and check_password_hash(temp_admin.password_hash, password):
            if temp_admin.expires_at < datetime.utcnow():
                flash('Temporary account has expired')
            else:
                session['temp_admin_logged_in'] = True
                session['temp_admin_username'] = temp_admin.username
                session['dark_mode'] = True
                session['is_temp_admin'] = True
                return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials')
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/login.html', active_theme=active_theme)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if session.get('is_temp_admin'):
        admin = TempAdminUser.query.filter_by(username=session['temp_admin_username']).first()
    else:
        admin = Admin.query.filter_by(username=session['admin_username']).first()
    messages = ContactMessage.query.order_by(ContactMessage.created_at.desc()).all()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/dashboard.html', messages=messages, dark_mode=session.get('dark_mode', True), 
                         active_theme=active_theme, current_route=request.endpoint, is_temp_admin=session.get('is_temp_admin', False))

@app.route('/admin/messages')
@login_required
def admin_messages():
    if session.get('is_temp_admin'):
        admin = TempAdminUser.query.filter_by(username=session['temp_admin_username']).first()
    else:
        admin = Admin.query.filter_by(username=session['admin_username']).first()
    messages = ContactMessage.query.order_by(ContactMessage.created_at.desc()).all()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/messages.html', messages=messages, dark_mode=session.get('dark_mode', True), 
                         active_theme=active_theme, is_temp_admin=session.get('is_temp_admin', False))

@app.route('/admin/certificates', methods=['GET', 'POST'])
@full_admin_required
def admin_certificates():
    admin = Admin.query.filter_by(username=session['admin_username']).first()
    if request.method == 'POST':
        try:
            if 'add_certificate' in request.form:
                title = request.form['title']
                description = request.form['description']
                icon_url = request.form.get('icon_url', '')
                verify_url = request.form.get('verify_url', '')
                image_link = request.form.get('imageLink', '')

                if image_link:  # If URL is provided
                    image_path = image_link
                else:  # If file is uploaded
                    if 'image' not in request.files or not request.files['image'].filename:
                        flash('Please provide an image file or URL')
                        return redirect(url_for('admin_certificates'))
                    file = request.files['image']
                    filename = f"certificate_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    image_path = filename

                new_certificate = Certificate(
                    title=title,
                    description=description,
                    image_path=image_path,
                    icon_url=icon_url,
                    verify_url=verify_url
                )
                db.session.add(new_certificate)
                log = ActionLog(admin_id=admin.id, action=f"Added certificate: {title}")
                db.session.add(log)
                db.session.commit()
                flash('Certificate added successfully!')
            elif 'delete_certificate' in request.form:
                cert_id = request.form['cert_id']
                certificate = Certificate.query.get_or_404(cert_id)
                if not certificate.image_path.startswith('http'):  # Only delete local files
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], certificate.image_path))
                    except OSError:
                        pass
                db.session.delete(certificate)
                log = ActionLog(admin_id=admin.id, action=f"Deleted certificate: {certificate.title}")
                db.session.add(log)
                db.session.commit()
                flash('Certificate deleted successfully!')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}')
        return redirect(url_for('admin_certificates'))
    
    certificates = Certificate.query.order_by(Certificate.created_at.desc()).all()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/certificates.html', admin=admin, certificates=certificates, 
                         dark_mode=session.get('dark_mode', True), active_theme=active_theme)

@app.route('/admin/projects', methods=['GET', 'POST'])
@full_admin_required
def admin_projects():
    admin = Admin.query.filter_by(username=session['admin_username']).first()
    if request.method == 'POST':
        try:
            if 'add_project' in request.form:
                title = request.form['title']
                category_id = request.form['category_id']
                gif_url = request.form['gif_url']
                link_url = request.form.get('link_url', '')
                online_url = request.form.get('online_url', '')
                
                new_project = Project(
                    title=title,
                    category_id=category_id,
                    gif_url=gif_url,
                    link_url=link_url,
                    online_url=online_url
                )
                db.session.add(new_project)
                log = ActionLog(admin_id=admin.id, action=f"Added project: {title}")
                db.session.add(log)
                db.session.commit()
                flash('Project added successfully!')
            elif 'delete_project' in request.form:
                project_id = request.form['project_id']
                project = Project.query.get_or_404(project_id)
                db.session.delete(project)
                log = ActionLog(admin_id=admin.id, action=f"Deleted project: {project.title}")
                db.session.add(log)
                db.session.commit()
                flash('Project deleted successfully!')
            elif 'add_category' in request.form:
                name = request.form['category_name']
                if Category.query.filter_by(name=name).first():
                    flash('Category already exists!')
                else:
                    new_category = Category(name=name)
                    db.session.add(new_category)
                    log = ActionLog(admin_id=admin.id, action=f"Added category: {name}")
                    db.session.add(log)
                    db.session.commit()
                    flash('Category added successfully!')
            elif 'delete_category' in request.form:
                category_id = request.form['category_id']
                category = Category.query.get_or_404(category_id)
                if category.projects:
                    flash('Cannot delete category with associated projects!')
                else:
                    db.session.delete(category)
                    log = ActionLog(admin_id=admin.id, action=f"Deleted category: {category.name}")
                    db.session.add(log)
                    db.session.commit()
                    flash('Category deleted successfully!')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}')
        return redirect(url_for('admin_projects'))
    
    projects = Project.query.order_by(Project.created_at.desc()).all()
    categories = Category.query.all()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/projects.html', admin=admin, projects=projects, categories=categories, 
                         dark_mode=session.get('dark_mode', True), active_theme=active_theme)

@app.route('/admin/githubprojects', methods=['GET', 'POST'])
@full_admin_required
def admin_githubprojects():
    admin = Admin.query.filter_by(username=session['admin_username']).first()
    if request.method == 'POST':
        try:
            if 'add_project' in request.form:
                title = request.form['title']
                description = request.form['description']
                github_url = request.form['github_url']
                online_url = request.form.get('online_url', '')
                avatar_url = request.form.get('avatar_url', 'https://github.com/prajwal032004/prajwal032004/blob/main/pngwing.com.png?raw=true')
                
                new_project = GitHubProject(
                    title=title,
                    description=description,
                    github_url=github_url,
                    online_url=online_url,
                    avatar_url=avatar_url
                )
                db.session.add(new_project)
                log = ActionLog(admin_id=admin.id, action=f"Added GitHub project: {title}")
                db.session.add(log)
                db.session.commit()
                flash('GitHub Project added successfully!')
            elif 'delete_project' in request.form:
                project_id = request.form['project_id']
                project = GitHubProject.query.get_or_404(project_id)
                db.session.delete(project)
                log = ActionLog(admin_id=admin.id, action=f"Deleted GitHub project: {project.title}")
                db.session.add(log)
                db.session.commit()
                flash('GitHub Project deleted successfully!')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}')
        return redirect(url_for('admin_githubprojects'))
    
    github_projects = GitHubProject.query.order_by(GitHubProject.created_at.desc()).all()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/githubprojects.html', admin=admin, github_projects=github_projects, 
                         dark_mode=session.get('dark_mode', True), active_theme=active_theme)

@app.route('/admin/settings', methods=['GET', 'POST'])
@full_admin_required
def admin_settings():
    admin = Admin.query.filter_by(username=session['admin_username']).first()
    if request.method == 'POST':
        try:
            if 'username' in request.form and request.form['username']:
                admin.username = request.form['username']
                session['admin_username'] = admin.username
            if 'password' in request.form and request.form['password']:
                admin.password_hash = generate_password_hash(request.form['password'])
            if 'welcome_message' in request.form:
                admin.welcome_message = request.form['welcome_message']
            admin.dark_mode = 'dark_mode' in request.form
            
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename:
                    filename = f"admin_profile_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    admin.profile_picture = filename

            session['dark_mode'] = admin.dark_mode
            log = ActionLog(admin_id=admin.id, action="Updated settings")
            db.session.add(log)
            db.session.commit()
            flash('Settings updated successfully!')
        except Exception as e:
            db.session.rollback()
            flash(f'Failed to update settings: {str(e)}')
        return redirect(url_for('admin_settings'))
    
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/settings.html', admin=admin, dark_mode=session.get('dark_mode', True), active_theme=active_theme)

@app.route('/admin/users', methods=['GET', 'POST'])
@full_admin_required
def admin_users():
    admin = Admin.query.filter_by(username=session['admin_username']).first()
    if request.method == 'POST':
        try:
            if 'add_user' in request.form:
                username = request.form['username']
                password = request.form['password']
                days = int(request.form.get('days', 7))
                if TempAdminUser.query.filter_by(username=username).first():
                    flash('Username already exists!')
                else:
                    new_user = TempAdminUser(
                        username=username,
                        password_hash=generate_password_hash(password),
                        expires_at=datetime.utcnow() + timedelta(days=days)
                    )
                    db.session.add(new_user)
                    log = ActionLog(admin_id=admin.id, action=f"Added temporary user {username} for {days} days")
                    db.session.add(log)
                    db.session.commit()
                    flash(f'Temporary user {username} added successfully! Expires in {days} days.')
            elif 'delete_user' in request.form:
                user_id = request.form['user_id']
                user = TempAdminUser.query.get_or_404(user_id)
                db.session.delete(user)
                log = ActionLog(admin_id=admin.id, action=f"Deleted temporary user {user.username}")
                db.session.add(log)
                db.session.commit()
                flash('Temporary user deleted successfully!')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}')
        return redirect(url_for('admin_users'))
    
    users = TempAdminUser.query.all()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/users.html', admin=admin, users=users, dark_mode=session.get('dark_mode', True), active_theme=active_theme)

@app.route('/admin/logs')
@login_required
def admin_logs():
    if session.get('is_temp_admin'):
        admin = TempAdminUser.query.filter_by(username=session['temp_admin_username']).first()
    else:
        admin = Admin.query.filter_by(username=session['admin_username']).first()
    logs = ActionLog.query.order_by(ActionLog.timestamp.desc()).all()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/logs.html', admin=admin, logs=logs, dark_mode=session.get('dark_mode', True), 
                         active_theme=active_theme, is_temp_admin=session.get('is_temp_admin', False))

@app.route('/admin/notifications', methods=['GET', 'POST'])
@full_admin_required
def admin_notifications():
    admin = Admin.query.filter_by(username=session['admin_username']).first()
    if request.method == 'POST':
        try:
            if 'add_notification' in request.form:
                message = request.form['message']
                new_notification = Notification(message=message)
                db.session.add(new_notification)
                log = ActionLog(admin_id=admin.id, action="Added notification")
                db.session.add(log)
                db.session.commit()
                flash('Notification added successfully!')
            elif 'toggle_notification' in request.form:
                notif_id = request.form['notif_id']
                notif = Notification.query.get_or_404(notif_id)
                notif.active = not notif.active
                log = ActionLog(admin_id=admin.id, action=f"Toggled notification {notif_id} to {notif.active}")
                db.session.add(log)
                db.session.commit()
                flash('Notification status updated!')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}')
        return redirect(url_for('admin_notifications'))
    
    notifications = Notification.query.order_by(Notification.created_at.desc()).all()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/notifications.html', admin=admin, notifications=notifications, 
                         dark_mode=session.get('dark_mode', True), active_theme=active_theme)

@app.route('/admin/themes', methods=['GET', 'POST'])
@full_admin_required
def admin_themes():
    admin = Admin.query.filter_by(username=session['admin_username']).first()
    if request.method == 'POST':
        try:
            if 'add_theme' in request.form:
                name = request.form['name']
                primary_color = request.form['primary_color']
                secondary_color = request.form['secondary_color']
                if Theme.query.filter_by(name=name).first():
                    flash('Theme name already exists!')
                else:
                    new_theme = Theme(name=name, primary_color=primary_color, secondary_color=secondary_color)
                    db.session.add(new_theme)
                    log = ActionLog(admin_id=admin.id, action=f"Added theme {name}")
                    db.session.add(log)
                    db.session.commit()
                    flash('Theme added successfully!')
            elif 'activate_theme' in request.form:
                theme_id = request.form['theme_id']
                Theme.query.update({Theme.active: False})
                theme = Theme.query.get_or_404(theme_id)
                theme.active = True
                log = ActionLog(admin_id=admin.id, action=f"Activated theme {theme.name}")
                db.session.add(log)
                db.session.commit()
                flash('Theme activated!')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}')
        return redirect(url_for('admin_themes'))
    
    themes = Theme.query.all()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/themes.html', admin=admin, themes=themes, active_theme=active_theme, 
                         dark_mode=session.get('dark_mode', True))

@app.route('/admin/delete/<int:message_id>', methods=['POST'])
@full_admin_required
def delete_message(message_id):
    admin = Admin.query.filter_by(username=session['admin_username']).first()
    message = ContactMessage.query.get_or_404(message_id)
    if message.attachment_path:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], message.attachment_path))
        except OSError:
            pass
    db.session.delete(message)
    log = ActionLog(admin_id=admin.id, action=f"Deleted message {message_id}")
    db.session.add(log)
    db.session.commit()
    flash('Message deleted successfully!')
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/admin/bulk_delete', methods=['POST'])
@full_admin_required
def bulk_delete():
    admin = Admin.query.filter_by(username=session['admin_username']).first()
    message_ids = request.form.getlist('message_ids')
    try:
        for message_id in message_ids:
            message = ContactMessage.query.get_or_404(int(message_id))
            if message.attachment_path:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], message.attachment_path))
                except OSError:
                    pass
            db.session.delete(message)
        log = ActionLog(admin_id=admin.id, action=f"Bulk deleted {len(message_ids)} messages")
        db.session.add(log)
        db.session.commit()
        flash(f'{len(message_ids)} message(s) deleted successfully!')
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to delete messages: {str(e)}')
    return redirect(url_for('admin_messages'))

@app.route('/admin/logout')
@login_required
def admin_logout():
    if session.get('is_temp_admin'):
        session.pop('temp_admin_logged_in', None)
        session.pop('temp_admin_username', None)
    else:
        admin = Admin.query.filter_by(username=session['admin_username']).first()
        if admin:
            log = ActionLog(admin_id=admin.id, action="Logged out")
            db.session.add(log)
            db.session.commit()
        session.pop('admin_logged_in', None)
        session.pop('admin_username', None)
    session.pop('dark_mode', None)
    session.pop('is_temp_admin', None)
    return redirect(url_for('admin_login'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin/export_csv', methods=['POST'])
@full_admin_required
def export_csv():
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    query = ContactMessage.query
    if start_date:
        query = query.filter(ContactMessage.created_at >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(ContactMessage.created_at <= datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))
    messages = query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Name', 'Email', 'Message', 'Attachment', 'Date'])
    for msg in messages:
        writer.writerow([msg.id, msg.name, msg.email, msg.message, msg.attachment_path or 'None', msg.created_at.strftime('%Y-%m-%d %H:%M:%S')])
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv', headers={"Content-Disposition": "attachment;filename=messages.csv"})

@app.route('/admin/backup_db', methods=['POST'])
@full_admin_required
def backup_db():
    admin = Admin.query.filter_by(username=session['admin_username']).first()
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    backup_file = f"backup_{timestamp}.db"
    shutil.copy('database.db', os.path.join(app.config['UPLOAD_FOLDER'], backup_file))
    log = ActionLog(admin_id=admin.id, action=f"Created database backup {backup_file}")
    db.session.add(log)
    db.session.commit()
    return send_from_directory(app.config['UPLOAD_FOLDER'], backup_file, as_attachment=True)

@app.route('/admin/search_messages', methods=['POST'])
@login_required
def search_messages():
    if session.get('is_temp_admin'):
        admin = TempAdminUser.query.filter_by(username=session['temp_admin_username']).first()
    else:
        admin = Admin.query.filter_by(username=session['admin_username']).first()
    query_str = request.form['query']
    results = ContactMessage.query.filter(
        or_(
            ContactMessage.name.ilike(f'%{query_str}%'),
            ContactMessage.email.ilike(f'%{query_str}%'),
            ContactMessage.message.ilike(f'%{query_str}%')
        )
    ).all()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/search.html', admin=admin, results=results, dark_mode=session.get('dark_mode', True), 
                         active_theme=active_theme, is_temp_admin=session.get('is_temp_admin', False))

@app.route('/admin/export')
@full_admin_required
def admin_export():
    admin = Admin.query.filter_by(username=session['admin_username']).first()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/export.html', admin=admin, dark_mode=session.get('dark_mode', True), active_theme=active_theme)

@app.route('/admin/backup')
@full_admin_required
def admin_backup():
    admin = Admin.query.filter_by(username=session['admin_username']).first()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/backup.html', admin=admin, dark_mode=session.get('dark_mode', True), active_theme=active_theme)

@app.route('/admin/search')
@login_required
def admin_search():
    if session.get('is_temp_admin'):
        admin = TempAdminUser.query.filter_by(username=session['temp_admin_username']).first()
    else:
        admin = Admin.query.filter_by(username=session['admin_username']).first()
    active_theme = Theme.query.filter_by(active=True).first() or Theme(name='Default', primary_color='#0ea5e9', secondary_color='#0284c7')
    return render_template('admin/search.html', admin=admin, dark_mode=session.get('dark_mode', True), 
                         active_theme=active_theme, current_route=request.endpoint, is_temp_admin=session.get('is_temp_admin', False))

@app.route('/admin/toggle_theme', methods=['POST'])
@login_required
def toggle_theme():
    data = request.get_json()
    dark_mode = data.get('dark_mode', False)
    if session.get('is_temp_admin'):
        session['dark_mode'] = dark_mode
    else:
        admin = Admin.query.filter_by(username=session['admin_username']).first()
        admin.dark_mode = dark_mode
        session['dark_mode'] = dark_mode
        db.session.commit()
    return '', 200

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)