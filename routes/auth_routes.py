"""
Authentication routes - login, register, logout
"""
import datetime
import jwt
import time
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session, flash
from email_validator import validate_email, EmailNotValidError
from functools import wraps
from models.database import User, db
from collections import defaultdict, deque
from pyFunctions.email_service import send_password_reset_email, send_welcome_email, send_otp_email

auth_bp = Blueprint('auth', __name__)

# Simple in-memory rate limiting (for production, use Redis or database)
login_attempts = defaultdict(deque)
registration_attempts = defaultdict(deque)
RATE_LIMIT_WINDOW = 300  # 5 minutes in seconds
MAX_LOGIN_ATTEMPTS = 5
MAX_REGISTRATION_ATTEMPTS = 3

def _prefers_json_response() -> bool:
    """Return True when request is coming from an API client rather than a browser form."""
    if request.is_json:
        return True
    best = request.accept_mimetypes.best
    if best == "application/json":
        return request.accept_mimetypes[best] >= request.accept_mimetypes["text/html"]
    return False

def is_rate_limited(ip_address, attempts_dict, max_attempts):
    """Check if IP is rate limited"""
    now = time.time()
    # Clean old attempts
    while attempts_dict[ip_address] and attempts_dict[ip_address][0] < now - RATE_LIMIT_WINDOW:
        attempts_dict[ip_address].popleft()
    
    return len(attempts_dict[ip_address]) >= max_attempts

def record_attempt(ip_address, attempts_dict):
    """Record an attempt for rate limiting"""
    attempts_dict[ip_address].append(time.time())

def token_required(f):
    """Token required decorator with improved security"""
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask import current_app
        import time
        
        token = session.get('token')
        if not token:
            # Add small random delay to prevent timing attacks
            time.sleep(0.01 + (hash(str(time.time())) % 100) / 10000)
            return redirect(url_for('auth.login'))

        try:
            data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                # Add small random delay to prevent timing attacks
                time.sleep(0.01 + (hash(str(time.time())) % 100) / 10000)
                return redirect(url_for('auth.login'))
        except jwt.ExpiredSignatureError:
            # Token has expired
            session.clear()
            return redirect(url_for('auth.logout') + '?timeout=true')
        except (jwt.InvalidTokenError, Exception):
            # Invalid token or other JWT errors
            session.clear()
            time.sleep(0.01 + (hash(str(time.time())) % 100) / 10000)
            return redirect(url_for('auth.login'))

        return f(current_user, *args, **kwargs)

    return decorated

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        wants_json = _prefers_json_response()
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Check rate limiting
        if is_rate_limited(ip_address, registration_attempts, MAX_REGISTRATION_ATTEMPTS):
            if wants_json:
                return jsonify({"error": "Too many registration attempts. Please try again in 5 minutes."}), 429
            flash("Too many registration attempts. Please try again in 5 minutes.", "error")
            return render_template("register.html"), 429
        
        record_attempt(ip_address, registration_attempts)
        
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()  # Normalize email to lowercase
        password = request.form.get("password", "").strip()  # Strip whitespace from password
        confirm_password = request.form.get("confirm_password", "").strip()  # Strip whitespace from password

        # Input validation
        if not name or not email or not password:
            if wants_json:
                return jsonify({"error": "All fields are required"}), 400
            flash("All fields are required.", "error")
            return render_template("register.html"), 400

        # Email validation
        try:
            validate_email(email)
        except EmailNotValidError as e:
            if wants_json:
                return jsonify({"error": str(e)}), 400
            flash(str(e), "error")
            return render_template("register.html"), 400

        # Password match check
        if password != confirm_password:
            if wants_json:
                return jsonify({"error": "Passwords do not match"}), 400
            flash("Passwords do not match.", "error")
            return render_template("register.html"), 400

        # Enhanced password strength check
        if len(password) < 8:
            if wants_json:
                return jsonify({"error": "Password must be at least 8 characters long"}), 400
            flash("Password must be at least 8 characters long.", "error")
            return render_template("register.html"), 400
        
        # Check for complexity
        if not any(c.isupper() for c in password):
            if wants_json:
                return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
            flash("Password must contain at least one uppercase letter.", "error")
            return render_template("register.html"), 400
        
        if not any(c.islower() for c in password):
            if wants_json:
                return jsonify({"error": "Password must contain at least one lowercase letter"}), 400
            flash("Password must contain at least one lowercase letter.", "error")
            return render_template("register.html"), 400
        
        if not any(c.isdigit() for c in password):
            if wants_json:
                return jsonify({"error": "Password must contain at least one number"}), 400
            flash("Password must contain at least one number.", "error")
            return render_template("register.html"), 400

        # Check if email exists
        if User.query.filter_by(email=email).first():
            if wants_json:
                return jsonify({"error": "Email already registered"}), 400
            flash("Email already registered.", "error")
            return render_template("register.html"), 400

        # Create user with properly hashed password
        new_user = User(name=name, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Send welcome email
        try:
            email_result = send_welcome_email(email, name)
            if not email_result['success']:
                print(f"Warning: Failed to send welcome email: {email_result['message']}")
        except Exception as e:
            print(f"Warning: Error sending welcome email: {str(e)}")

        return redirect(url_for('auth.login'))

    return render_template("register.html")

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        wants_json = _prefers_json_response()
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Check rate limiting
        if is_rate_limited(ip_address, login_attempts, MAX_LOGIN_ATTEMPTS):
            if wants_json:
                return jsonify({"error": "Too many login attempts. Please try again in 5 minutes."}), 429
            flash("Too many login attempts. Please try again in 5 minutes.", "error")
            return render_template("login.html"), 429
        
        email = request.form.get("email", "").strip().lower()  # Normalize email to lowercase
        password = request.form.get("password", "").strip()  # Strip whitespace from password

        # Input validation
        if not email or not password:
            record_attempt(ip_address, login_attempts)
            if wants_json:
                return jsonify({"error": "Email and password are required"}), 400
            flash("Email and password are required.", "error")
            return render_template("login.html"), 400

        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            record_attempt(ip_address, login_attempts)
            if wants_json:
                return jsonify({"error": "Invalid credentials"}), 401
            flash("Invalid credentials.", "error")
            return render_template("login.html"), 401

        # Generate JWT with shorter expiration for security
        from flask import current_app
        token = jwt.encode(
            {
                "user_id": user.id,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
                "iat": datetime.datetime.utcnow()
            },
            current_app.config['JWT_SECRET_KEY'],
            algorithm="HS256"
        )

        # Store token in session
        session['token'] = token
        session['user_name'] = user.name

        # Redirect to dashboard
        return redirect(url_for('dashboard'))

    return render_template("login.html")

@auth_bp.route('/logout')
def logout():
    session.pop('token', None)
    session.pop('user_name', None)
    session.pop('simulation_phase', None)
    session.pop('current_email_id', None)
    session.pop('simulation_id', None)
    session.pop('phase2_emails_completed', None)
    session.pop('active_phase2_email_id', None)
    
    # Check if timeout parameter is present
    timeout = request.args.get('timeout', False)
    if timeout:
        flash("Your session has expired due to inactivity. Please login again.")
    
    return redirect(url_for('auth.login'))

@auth_bp.route('/extend_session', methods=['POST'])
@token_required
def extend_session(current_user):
    # Renew the JWT token with a fresh expiry
    from flask import current_app
    token = jwt.encode(
        {
            "user_id": current_user.id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        },
        current_app.config['JWT_SECRET_KEY'],
        algorithm="HS256"
    )
    
    # Update the session token
    session['token'] = token
    
    return jsonify({"success": True, "message": "Session extended"}), 200

def admin_required(f):
    """Admin required decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # This should be called after token_required
        current_user = args[0] if args else None
        if not current_user or not current_user.is_admin_user():
            flash("Admin access required.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

@auth_bp.route('/demographics', methods=['GET', 'POST'])
@token_required
def demographics(current_user):
    if request.method == 'POST':
        current_user.tech_confidence = request.form.get('tech_confidence', '').strip()
        current_user.cybersecurity_experience = request.form.get('cybersecurity_experience', '').strip()
        current_user.age_group = request.form.get('age_group', '').strip()
        current_user.industry = request.form.get('industry', '').strip()
        current_user.demographics_completed = True
        db.session.commit()
        return redirect(url_for('analysis.learn'))
    return render_template('demographics.html', username=current_user.name, user=current_user)

@auth_bp.route('/profile', methods=['GET', 'POST'])
@token_required
def profile(current_user):
    if request.method == 'POST':
        current_user.tech_confidence = request.form.get('tech_confidence', '').strip()
        current_user.cybersecurity_experience = request.form.get('cybersecurity_experience', '').strip()
        current_user.age_group = request.form.get('age_group', '').strip()
        current_user.industry = request.form.get('industry', '').strip()
        current_user.demographics_completed = True
        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for('auth.profile'))
    return render_template('profile.html', username=current_user.name, user=current_user)

@auth_bp.route('/admin/users')
@token_required
@admin_required
def admin_users(current_user):
    """Admin view to see all registered users"""
    users = User.query.all()
    return render_template('admin_users.html', 
                         users=users, 
                         username=current_user.name,
                         current_user=current_user)

@auth_bp.route('/admin/make_admin/<int:user_id>', methods=['POST'])
@token_required 
@admin_required
def make_admin(current_user, user_id):
    """Make a user an admin"""
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    
    flash(f"Successfully made {user.name} an admin.", "success")
    return redirect(url_for('auth.admin_users'))

@auth_bp.route('/reset-password', methods=['GET'])
def reset_password_legacy_link():
    """Backward-compatible password reset link handler (?token=...)."""
    token = request.args.get('token', '').strip()
    if not token:
        flash("Invalid password reset link.", "error")
        return redirect(url_for('auth.login'))
    return redirect(url_for('auth.reset_password', token=token))

@auth_bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    """Request password reset"""
    if request.method == 'POST':
        wants_json = _prefers_json_response()
        email = request.form.get('email', '').strip().lower()  # Normalize email to lowercase
        
        if not email:
            if wants_json:
                return jsonify({"error": "Email is required"}), 400
            flash("Email is required.", "error")
            return render_template('reset_password_request.html'), 400
            
        user = User.query.filter_by(email=email).first()
        if user:
            token = user.generate_reset_token()
            db.session.commit()
            
            # Send password reset email using Resend
            try:
                email_result = send_password_reset_email(email, token, user.name)
                if email_result['success']:
                    flash(f"Password reset instructions have been sent to {email}.", "info")
                else:
                    # Fallback to console logging if email fails
                    reset_url = url_for('auth.reset_password', token=token, _external=True)
                    print(f"Password reset requested for {email}")
                    print(f"Reset URL: {reset_url}")
                    flash(f"Password reset link generated. Check console: {reset_url}", "info")
            except Exception as e:
                # Fallback to console logging if email service fails
                reset_url = url_for('auth.reset_password', token=token, _external=True)
                print(f"Email service error: {str(e)}")
                print(f"Password reset requested for {email}")
                print(f"Reset URL: {reset_url}")
                flash(f"Password reset link generated. Check console for the link.", "info")
        else:
            # Don't reveal that email doesn't exist for security
            flash(f"If an account with {email} exists, password reset instructions have been sent.", "info")
            
        return redirect(url_for('auth.login'))
    
    return render_template('reset_password_request.html')

@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password with token"""
    user = User.query.filter_by(password_reset_token=token).first()
    
    if not user or not user.verify_reset_token(token):
        flash("Invalid or expired password reset token.", "error")
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        wants_json = _prefers_json_response()
        password = request.form.get('password', '').strip()  # Strip whitespace from password
        confirm_password = request.form.get('confirm_password', '').strip()  # Strip whitespace from password
        
        # Password validation (same as registration)
        if not password:
            if wants_json:
                return jsonify({"error": "Password is required"}), 400
            flash("Password is required.", "error")
            return render_template('reset_password.html', token=token), 400
            
        if password != confirm_password:
            if wants_json:
                return jsonify({"error": "Passwords do not match"}), 400
            flash("Passwords do not match.", "error")
            return render_template('reset_password.html', token=token), 400
            
        # Enhanced password strength check
        if len(password) < 8:
            if wants_json:
                return jsonify({"error": "Password must be at least 8 characters long"}), 400
            flash("Password must be at least 8 characters long.", "error")
            return render_template('reset_password.html', token=token), 400
        
        if not any(c.isupper() for c in password):
            if wants_json:
                return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
            flash("Password must contain at least one uppercase letter.", "error")
            return render_template('reset_password.html', token=token), 400
        
        if not any(c.islower() for c in password):
            if wants_json:
                return jsonify({"error": "Password must contain at least one lowercase letter"}), 400
            flash("Password must contain at least one lowercase letter.", "error")
            return render_template('reset_password.html', token=token), 400
        
        if not any(c.isdigit() for c in password):
            if wants_json:
                return jsonify({"error": "Password must contain at least one number"}), 400
            flash("Password must contain at least one number.", "error")
            return render_template('reset_password.html', token=token), 400
        
        # Update password and clear reset token
        user.set_password(password)
        user.clear_reset_token()
        db.session.commit()
        
        flash("Your password has been reset successfully. Please log in.", "success")
        return redirect(url_for('auth.login'))
    
    return render_template('reset_password.html', token=token)

# OTP-based password reset routes
@auth_bp.route('/request_password_reset_otp', methods=['POST'])
def request_password_reset_otp():
    """Request OTP for password reset (API endpoint for React frontend)"""
    data = request.get_json()
    email = data.get('email', '').strip() if data else request.form.get('email', '').strip()
    
    if not email:
        return jsonify({"success": False, "error": "Email is required"}), 400
    
    # Validate email format
    try:
        validate_email(email)
    except EmailNotValidError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    
    user = User.query.filter_by(email=email).first()
    if user:
        # Generate OTP
        otp = user.generate_otp()
        db.session.commit()
        
        # Send OTP email
        try:
            email_result = send_otp_email(email, otp, user.name)
            if email_result['success']:
                return jsonify({
                    "success": True,
                    "message": "OTP sent to your email address"
                }), 200
            else:
                # Log error but don't reveal it to user
                print(f"Failed to send OTP email: {email_result['message']}")
                return jsonify({
                    "success": False,
                    "error": "Failed to send OTP. Please try again later."
                }), 202
        except Exception as e:
            print(f"Error sending OTP: {str(e)}")
            return jsonify({
                "success": False,
                "error": "Failed to send OTP. Please try again later."
            }), 202
    else:
        # Don't reveal that email doesn't exist (security best practice)
        # Return success anyway
        return jsonify({
            "success": True,
            "message": "If an account with that email exists, an OTP has been sent"
        }), 200

@auth_bp.route('/verify_otp', methods=['POST'])
def verify_otp():
    """Verify OTP (API endpoint for React frontend)"""
    data = request.get_json()
    email = data.get('email', '').strip() if data else ''
    otp = data.get('otp', '').strip() if data else ''
    
    if not email or not otp:
        return jsonify({"success": False, "error": "Email and OTP are required"}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "error": "Invalid OTP"}), 400
    
    if user.verify_otp(otp):
        # OTP is valid - generate a temporary reset token for the next step
        import secrets
        reset_token = secrets.token_urlsafe(32)
        session[f'reset_token_{email}'] = reset_token
        session[f'reset_token_time_{email}'] = time.time()
        
        # Clear OTP but keep it in session for final password reset
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "OTP verified successfully",
            "reset_token": reset_token
        }), 200
    else:
        db.session.commit()  # Save incremented attempt counter
        attempts_left = 5 - user.otp_attempts
        if attempts_left <= 0:
            return jsonify({
                "success": False,
                "error": "Too many failed attempts. Please request a new OTP."
            }), 429
        return jsonify({
            "success": False,
            "error": f"Invalid OTP. {attempts_left} attempts remaining."
        }), 400

@auth_bp.route('/reset_password_with_otp', methods=['POST'])
def reset_password_with_otp():
    """Reset password after OTP verification (API endpoint for React frontend)"""
    data = request.get_json()
    email = data.get('email', '').strip() if data else ''
    reset_token = data.get('reset_token', '').strip() if data else ''
    new_password = data.get('new_password', '') if data else ''
    
    if not email or not reset_token or not new_password:
        return jsonify({"success": False, "error": "All fields are required"}), 400
    
    # Verify reset token from session
    session_token = session.get(f'reset_token_{email}')
    session_time = session.get(f'reset_token_time_{email}', 0)
    
    if not session_token or session_token != reset_token:
        return jsonify({"success": False, "error": "Invalid reset token"}), 400
    
    # Check if token expired (15 minutes)
    if time.time() - session_time > 900:
        session.pop(f'reset_token_{email}', None)
        session.pop(f'reset_token_time_{email}', None)
        return jsonify({"success": False, "error": "Reset token expired. Please start over."}), 400
    
    # Validate password
    if len(new_password) < 8:
        return jsonify({"success": False, "error": "Password must be at least 8 characters long"}), 400
    
    if not any(c.isupper() for c in new_password):
        return jsonify({"success": False, "error": "Password must contain at least one uppercase letter"}), 400
    
    if not any(c.islower() for c in new_password):
        return jsonify({"success": False, "error": "Password must contain at least one lowercase letter"}), 400
    
    if not any(c.isdigit() for c in new_password):
        return jsonify({"success": False, "error": "Password must contain at least one number"}), 400
    
    # Find user and update password
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404
    
    # Update password and clear OTP
    user.set_password(new_password)
    user.clear_otp()
    db.session.commit()
    
    # Clear session tokens
    session.pop(f'reset_token_{email}', None)
    session.pop(f'reset_token_time_{email}', None)
    
    return jsonify({
        "success": True,
        "message": "Password reset successfully"
    }), 200

@auth_bp.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@token_required
@admin_required
def admin_reset_password(current_user, user_id):
    """Admin function to reset any user's password"""
    user = User.query.get_or_404(user_id)
    
    new_password = request.form.get('new_password', '').strip()  # Strip whitespace from password
    confirm_password = request.form.get('confirm_password', '').strip()  # Strip whitespace from password
    
    # Validation
    if not new_password or not confirm_password:
        flash("Both password fields are required.", "error")
        return redirect(url_for('auth.admin_users'))
    
    if new_password != confirm_password:
        flash("Passwords do not match.", "error")
        return redirect(url_for('auth.admin_users'))
    
    # Enhanced password strength check
    if len(new_password) < 8:
        flash("Password must be at least 8 characters long.", "error")
        return redirect(url_for('auth.admin_users'))
    
    if not any(c.isupper() for c in new_password):
        flash("Password must contain at least one uppercase letter.", "error")
        return redirect(url_for('auth.admin_users'))
    
    if not any(c.islower() for c in new_password):
        flash("Password must contain at least one lowercase letter.", "error")
        return redirect(url_for('auth.admin_users'))
    
    if not any(c.isdigit() for c in new_password):
        flash("Password must contain at least one number.", "error")
        return redirect(url_for('auth.admin_users'))
    
    # Update password
    user.set_password(new_password)
    db.session.commit()
    
    flash(f"Password successfully reset for {user.name}.", "success")
    return redirect(url_for('auth.admin_users'))

@auth_bp.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@token_required
@admin_required 
def delete_user(current_user, user_id):
    """Admin function to delete a user account"""
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('auth.admin_users'))
    
    # Store user name for confirmation message
    user_name = user.name
    
    # Delete related records first (to maintain referential integrity)
    from models.database import SimulationResponse, SimulationSession
    SimulationResponse.query.filter_by(user_id=user.id).delete()
    SimulationSession.query.filter_by(user_id=user.id).delete()
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    
    flash(f"User {user_name} has been successfully deleted.", "success")
    return redirect(url_for('auth.admin_users'))
