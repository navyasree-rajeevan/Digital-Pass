import sqlite3
import uuid
import qrcode
import base64
from io import BytesIO
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from werkzeug.security import generate_password_hash, check_password_hash

# --- App Setup and Configuration ---
app = Flask(__name__)
app.secret_key = 'super-secret-key-for-session'
DATABASE = 'database.db'

# Define user roles for easy access
ROLES = ['Admin', 'Officer', 'Agency', 'Visitor'] 

# --- Database Utilities ---

def get_db():
    """Returns the database connection, creating it if necessary."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # This allows accessing columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database tables and inserts dummy data."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 1. Users Table (for all roles)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')

        # 2. Pass Types Table (Still needed if other parts of the app use it, but stripped from Admin UI)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pass_types (
                id INTEGER PRIMARY KEY,
                type_name TEXT UNIQUE NOT NULL,
                description TEXT
            )
        ''')
        
        # 3. Pass Requests Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pass_requests (
                id INTEGER PRIMARY KEY,
                visitor_id INTEGER NOT NULL,
                status TEXT NOT NULL, -- 'pending', 'approved', 'rejected'
                request_date TEXT NOT NULL,
                details TEXT,
                unique_code TEXT,
                pass_type_id INTEGER, 
                FOREIGN KEY (visitor_id) REFERENCES users(id),
                FOREIGN KEY (pass_type_id) REFERENCES pass_types(id)
            )
        ''')

        # 4. Audit Log Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                action_id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                user_role TEXT NOT NULL,
                action_type TEXT NOT NULL, -- 'approve', 'reject'
                timestamp TEXT NOT NULL,
                request_id INTEGER,
                FOREIGN KEY (request_id) REFERENCES pass_requests(id)
            )
        ''')

        # Insert Dummy Users if none exist
        if cursor.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
            dummy_users = [
                ('Alice Admin', 'admin@example.com', 'Admin', generate_password_hash('adminpass')),
                ('Officer Bob', 'officer@example.com', 'Officer', generate_password_hash('officerpass')),
                ('Agency Carl', 'agency@example.com', 'Agency', generate_password_hash('agencypass')),
                ('Visitor Dave', 'visitor@example.com', 'Visitor', generate_password_hash('visitorpass'))
            ]
            for name, email, role, pw_hash in dummy_users:
                cursor.execute(
                    "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
                    (name, email, pw_hash, role)
                )
            
            # Insert Dummy Pass Types (Referenced by pass_requests)
            cursor.execute(
                "INSERT INTO pass_types (type_name, description) VALUES (?, ?)",
                ('Standard Day Pass', 'One-day access for general visitors')
            )
            cursor.execute(
                "INSERT INTO pass_types (type_name, description) VALUES (?, ?)",
                ('Contractor Weekly', 'Seven-day pass for external contractors')
            )

            # Insert a Sample Pass Request (Assuming Visitor Dave is user ID 4)
            cursor.execute(
                "INSERT INTO pass_requests (visitor_id, status, request_date, details, unique_code, pass_type_id) VALUES (?, ?, ?, ?, ?, ?)",
                (4, 'pending', datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'Site visit for project X', None, 1)
            )

        db.commit()

# --- Utility Functions ---

def login_required(role=None):
    """Decorator to enforce login and optional role check."""
    def wrapper(f):
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if role and session.get('user_role') not in role:
                return "Unauthorized Access", 403
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__ # Fix for Flask routing
        return decorated_function
    if isinstance(role, str):
        role = [role]
    return wrapper

def generate_qr_code(data):
    """Generates a QR code for the given data and returns it as a Base64 string."""
    url_base = "http://127.0.0.1:5000" 
    validation_link = f"{url_base}{url_for('validate_pass')}?code={data}"

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(validation_link)
    qr.make(fit=True)

    buffered = BytesIO()
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(buffered, format="PNG")
    
    return base64.b64encode(buffered.getvalue()).decode('utf-8')

# --- Authentication and Dashboard Routes ---

@app.route('/')
def index():
    """Redirects authenticated users to their dashboard, unauthenticated to login."""
    if 'user_id' in session:
        role = session['user_role']
        if role == 'Visitor':
            return redirect(url_for('visitor_dashboard'))
        elif role == 'Officer':
            return redirect(url_for('officer_dashboard'))
        elif role == 'Admin':
            return redirect(url_for('admin_dashboard')) 
        elif role == 'Agency':
             return redirect(url_for('agency_dashboard'))
        return render_template('base.html', title=f"{role} Dashboard")
    
    # Go straight to the login page for unauthenticated users
    return redirect(url_for('login')) 
    
@app.route('/intro')
def intro():
    return render_template('intro.html')

@app.route('/redirect')
def redirect_portal():
    return render_template('redirect.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_role'] = user['role']
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials.", 'error')
            return render_template('login.html', error="Invalid credentials.")
    return render_template('login.html', title="Login")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        if role not in ['Visitor', 'Agency']:
            flash("Invalid role selection.", 'error')
            return render_template('register.html', error="Invalid role selection.", title="Register")

        password_hash = generate_password_hash(password)
        db = get_db()

        try:
            db.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (name, email, password_hash, role)
            )
            db.commit()
            flash("Registration successful. Please log in.", 'success')
            return redirect(url_for('login'))
        
        except sqlite3.IntegrityError:
            flash("Email already registered.", 'error')
            return render_template('register.html', error="Email already registered.", title="Register")

    return render_template('register.html', title="Register")

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required(role='Admin')
def admin_dashboard():
    db = get_db()
    
    if request.method == 'POST':
        # 1. Handle Add Officer Form
        if 'officer_name' in request.form:
            name = request.form['officer_name']
            email = request.form['officer_email']
            password = request.form['officer_password']
            password_hash = generate_password_hash(password)
            try:
                db.execute(
                    "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
                    (name, email, password_hash, 'Officer')
                )
                db.commit()
                # FLASH SUCCESS MESSAGE
                flash(f"Officer {name} ({email}) has been successfully added and can now log in.", 'success')
            except sqlite3.IntegrityError:
                flash(f"Error: Email {email} is already registered.", 'error')
                
        # 2. Handle Add Pass Type Form (REMOVED LOGIC)
        # The logic for adding pass types is removed as requested.
        pass

    # Fetch data for GET request (and after POST)
    
    # Fetch all Officer users (role='Officer')
    officers = db.execute(
        "SELECT id AS officer_id, name, email FROM users WHERE role = 'Officer' ORDER BY name"
    ).fetchall()
    
    # Note: We no longer fetch pass_types for display

    return render_template(
        'admin_dashboard.html', 
        officers=officers, 
        # pass_types=pass_types, <-- Removed from context
        title="Admin Dashboard"
    )

@app.route('/visitor_dashboard')
@login_required(role='Visitor')
def visitor_dashboard():
    visitor_id = session['user_id']
    db = get_db()
    
    request_data = db.execute(
        "SELECT * FROM pass_requests WHERE visitor_id = ? ORDER BY request_date DESC LIMIT 1",
        (visitor_id,)
    ).fetchone()

    qr_base64 = None
    if request_data and request_data['status'] == 'approved' and request_data['unique_code']:
        qr_base64 = generate_qr_code(request_data['unique_code'])

    return render_template(
        'visitor_dashboard.html', 
        request=request_data, 
        qr_base64=qr_base64,
        title="Visitor Pass Dashboard"
    )

@app.route('/officer_dashboard')
@login_required(role='Officer')
def officer_dashboard():
    db = get_db()
    
    pending_requests = db.execute("""
        SELECT pr.*, u.name as visitor_name
        FROM pass_requests pr
        JOIN users u ON pr.visitor_id = u.id
        WHERE pr.status = 'pending'
        ORDER BY pr.request_date ASC
    """).fetchall()

    return render_template(
        'officer_dashboard.html', 
        pending_requests=pending_requests,
        title="Officer Review Dashboard"
    )
    
@app.route('/agency_dashboard')
@login_required(role='Agency')
def agency_dashboard():
    return render_template('agency_dashboard.html', officers=[], pass_types=[], title="Agency Dashboard")

@app.route('/request_pass', methods=['GET', 'POST'])
@login_required(role='Visitor')
def request_pass():
    db = get_db()
    
    if request.method == 'POST':
        visitor_id = session['user_id']
        details = request.form['details']
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            db.execute(
                "INSERT INTO pass_requests (visitor_id, status, request_date, details) VALUES (?, ?, ?, ?)",
                (visitor_id, 'pending', current_time, details)
            )
            db.commit()
            return redirect(url_for('visitor_dashboard'))
        except Exception as e:
            print(f"Error submitting pass request: {e}")
            flash("Failed to submit request.", 'error')
            return render_template('request_pass.html', error="Failed to submit request.", title="Request Pass")

    return render_template('request_pass.html', title="Request Pass")

@app.route('/update_request', methods=['POST'])
@login_required(role='Officer')
def update_request():
    db = get_db()
    request_id = request.form.get('request_id')
    action = request.form.get('action') # 'approve' or 'reject'
    officer_id = session['user_id']
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    unique_code = None

    if action == 'approve':
        unique_code = uuid.uuid4().hex[:12].upper()
        db.execute(
            "UPDATE pass_requests SET status = ?, unique_code = ? WHERE id = ?",
            ('approved', unique_code, request_id)
        )
        flash(f"Request #{request_id} approved. Unique Code: {unique_code}", 'success')
    elif action == 'reject':
        db.execute(
            "UPDATE pass_requests SET status = ?, unique_code = ? WHERE id = ?",
            ('rejected', None, request_id)
        )
        flash(f"Request #{request_id} rejected.", 'error')
    else:
        return redirect(url_for('officer_dashboard'))

    # Log the action in the audit log
    db.execute(
        "INSERT INTO audit_log (user_id, user_role, action_type, timestamp, request_id) VALUES (?, ?, ?, ?, ?)",
        (officer_id, session['user_role'], action, current_time, request_id)
    )
    
    db.commit()
    return redirect(url_for('officer_dashboard'))

@app.route('/audit_log')
@login_required(role=['Admin', 'Officer'])
def audit_log():
    db = get_db()
    
    logs = db.execute("""
        SELECT 
            al.*, 
            u.name as user_name, 
            pr.visitor_id,
            pr.unique_code
        FROM audit_log al
        JOIN users u ON al.user_id = u.id
        LEFT JOIN pass_requests pr ON al.request_id = pr.id
        ORDER BY al.timestamp DESC
    """).fetchall()
    
    return render_template('audit_log.html', logs=logs, title="System Audit Log")

@app.route('/validate_pass', methods=['GET', 'POST'])
@login_required(role='Officer')
def validate_pass():
    code = request.args.get('code') or request.form.get('code')
    validation_result = None
    
    if code:
        code = code.strip().upper()
        db = get_db()
        
        pass_data = db.execute(
            """
            SELECT pr.*, u.name as visitor_name, u.email as visitor_email
            FROM pass_requests pr
            JOIN users u ON pr.visitor_id = u.id
            WHERE pr.unique_code = ?
            """,
            (code,)
        ).fetchone()

        if pass_data:
            status = pass_data['status']
            
            if status == 'approved':
                display_status = 'VALID & APPROVED'
                message = f"Access Granted. Visitor '{pass_data['visitor_name']}' is authorized. Details: {pass_data['details']}"
            elif status == 'rejected':
                display_status = 'REJECTED'
                message = f"Access Denied. This pass code belongs to a rejected request by {pass_data['visitor_name']}."
            else: # status == 'pending'
                display_status = 'PENDING'
                message = f"Pass is pending review. Access DENIED for {pass_data['visitor_name']}."
                
            validation_result = {
                'status': display_status,
                'message': message,
                'data': dict(pass_data)
            }
        else:
            validation_result = {
                'status': 'INVALID CODE',
                'message': "ERROR: Pass code not found in the system. Access Denied.",
                'data': None
            }

    return render_template('validate_pass.html', validation_result=validation_result, title="Validate Visitor Pass")


# Run the application
if __name__ == '__main__':
    init_db()  
    app.run(debug=True,host='127.0.0.1',port=5000)
