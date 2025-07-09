from flask import Flask, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import fitz  # PyMuPDF
import spacy
from reportlab.pdfgen import canvas
from io import BytesIO

# Target skills
TARGET_SKILLS = [
    "python", "java", "sql", "html", "css", "javascript", "react",
    "django", "flask", "git", "linux", "aws", "excel", "data analysis",
    "machine learning", "communication", "problem solving"
]

# Load spaCy
nlp = spacy.load("en_core_web_sm")

# Flask setup
app = Flask(__name__)
app.secret_key = "your_secret_key"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB

ALLOWED_EXTENSIONS = {'pdf'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return redirect(url_for('login'))

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for('signup'))

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful!", "success")
        return redirect(url_for('login'))

    return '''
    <html><head><title>Signup</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-light"><div class="container mt-5">
    <h2>Signup</h2><form method="post">
    <input name="username" class="form-control mb-2" placeholder="Username" required>
    <input name="password" type="password" class="form-control mb-2" placeholder="Password" required>
    <button class="btn btn-primary">Signup</button></form>
    <p class="mt-2">Already have an account? <a href="/login">Login</a></p>
    </div></body></html>'''

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash("Invalid credentials!", "danger")

    return '''
    <html><head><title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-light"><div class="container mt-5">
    <h2>Login</h2><form method="post">
    <input name="username" class="form-control mb-2" placeholder="Username" required>
    <input name="password" type="password" class="form-control mb-2" placeholder="Password" required>
    <button class="btn btn-success">Login</button></form>
    <p class="mt-2">New user? <a href="/signup">Signup</a></p>
    </div></body></html>'''

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return f'''
    <html><head><title>Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-light"><div class="container mt-5">
    <h2>Welcome, {current_user.username}!</h2>
    <a href="/upload" class="btn btn-primary me-2">Upload Resume</a>
    <a href="/analyze" class="btn btn-success me-2">Analyze Resume</a>
    <a href="/report" class="btn btn-info me-2">Download Report</a>
    <a href="/match" class="btn btn-warning me-2">Job Description Match</a>
    <a href="/logout" class="btn btn-danger">Logout</a>
    </div></body></html>'''

# Upload Resume
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_resume():
    if request.method == 'POST':
        file = request.files.get('resume')
        if file and allowed_file(file.filename):
            filename = f"{current_user.username}_resume.pdf"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('Uploaded successfully!', 'success')
            return redirect(url_for('dashboard'))
        flash('Please upload a PDF file.', 'danger')
    return '''
    <html><head><title>Upload</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-light"><div class="container mt-5">
    <h2>Upload Resume (PDF only)</h2>
    <form method="post" enctype="multipart/form-data">
    <input type="file" name="resume" class="form-control mb-2" required>
    <button class="btn btn-primary">Upload</button></form>
    <a href="/dashboard" class="btn btn-secondary mt-3">Back</a>
    </div></body></html>'''

# Analyze Resume
@app.route('/analyze')
@login_required
def analyze_resume():
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{current_user.username}_resume.pdf")
    if not os.path.exists(filepath):
        return "No resume uploaded. <a href='/upload'>Upload</a>"

    text = ''.join(page.get_text() for page in fitz.open(filepath))
    tokens = {t.text for t in nlp(text.lower()) if t.text in TARGET_SKILLS}
    match = len(tokens) / len(TARGET_SKILLS) * 100

    return f'''
    <html><head><title>Analysis</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-light"><div class="container mt-5">
    <h2>Match Score: {match:.2f}%</h2>
    <p><strong>Skills Found:</strong> {', '.join(tokens)}</p>
    <canvas id="chart" width="300" height="300"></canvas>
    <a class="btn btn-secondary mt-3" href="/dashboard">Back</a>
    </div>
    <script>
    new Chart(document.getElementById('chart'), {{
        type: 'doughnut',
        data: {{
            labels: ['Matched', 'Missing'],
            datasets: [{{ data: [{match:.2f}, {100 - match:.2f}], backgroundColor: ['#4CAF50', '#ccc'] }}]
        }},
        options: {{ cutout: '70%', plugins: {{ title: {{ display: true, text: 'Skill Match' }} }} }}
    }});
    </script></body></html>'''

# PDF Report
@app.route('/report')
@login_required
def generate_pdf_report():
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{current_user.username}_resume.pdf")
    if not os.path.exists(filepath):
        return "No resume uploaded."

    text = ''.join(page.get_text() for page in fitz.open(filepath))
    found = {t.text for t in nlp(text.lower()) if t.text in TARGET_SKILLS}
    missing = [s for s in TARGET_SKILLS if s not in found]
    match = len(found) / len(TARGET_SKILLS) * 100

    buf = BytesIO()
    p = canvas.Canvas(buf)
    p.drawString(50, 800, f"Resume Report - {current_user.username}")
    p.drawString(50, 780, f"Match: {match:.2f}%")
    y = 760
    p.drawString(50, y, "Skills Found:")
    for s in found:
        y -= 15
        p.drawString(70, y, f"- {s}")
    y -= 20
    p.drawString(50, y, "Missing Skills:")
    for s in missing:
        y -= 15
        p.drawString(70, y, f"- {s}")
    p.save()
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="resume_report.pdf")

# Job Description Matching
@app.route('/match', methods=['GET', 'POST'])
@login_required
def job_description_match():
    match_percent = None
    matched = []
    missing = []

    if request.method == 'POST':
        jd_text = request.form['jd']
        resume_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{current_user.username}_resume.pdf")
        if not os.path.exists(resume_path):
            return "Upload resume first."

        resume_text = ''.join(page.get_text() for page in fitz.open(resume_path))
        resume_words = {token.text.lower() for token in nlp(resume_text) if token.is_alpha and not token.is_stop}
        jd_words = {token.text.lower() for token in nlp(jd_text) if token.is_alpha and not token.is_stop}

        matched = list(resume_words & jd_words)
        missing = list(jd_words - resume_words)
        match_percent = (len(matched) / len(jd_words)) * 100 if jd_words else 0

    return f'''
    <html><head><title>JD Match</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-light"><div class="container mt-5">
    <h2>Job Description Match</h2>
    <form method="post">
    <textarea name="jd" class="form-control mb-3" rows="6" placeholder="Paste job description here..." required></textarea>
    <button class="btn btn-primary">Check Match</button>
    </form>
    {'<h4 class="mt-4">Match Score: {:.2f}%</h4>'.format(match_percent) if match_percent is not None else ''}
    {'<h5 class="mt-3">Matched Terms:</h5><p>' + ', '.join(matched) + '</p>' if matched else ''}
    {'<h5>Missing Terms:</h5><p>' + ', '.join(missing) + '</p>' if missing else ''}
    <a href="/dashboard" class="btn btn-secondary mt-3">Back</a>
    </div></body></html>'''

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

# Run
if __name__ == "__main__":
    app.run(debug=True)
