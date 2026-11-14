import os
import secrets
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

load_dotenv()

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect  
from flask_mail import Mail, Message
from flask import Flask, render_template, request, redirect, url_for, session, flash
from app.models import db, User, ScanHistory, PasswordReset
from werkzeug.security import generate_password_hash, check_password_hash

from ai.predictor import predict_email
import re

from cybersecurity.url_checker import analyze_email_urls
from cybersecurity.keyword_checker import analyze_keywords
from cybersecurity.header_checker import analyze_headers
from cybersecurity.sender_checker import analyze_sender
from cybersecurity.threat_score import calculate_threat_score

app = Flask(
    __name__,
    template_folder="app/templates",
    static_folder="app/static"
)


app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY environment variable is not set")

database_url = os.environ.get("DATABASE_URL")

if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://",
        "postgresql://",
        1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "True"
)


print("========== MAIL CONFIG ==========")
print("MAIL_SERVER:", app.config.get("MAIL_SERVER"))
print("MAIL_PORT:", app.config.get("MAIL_PORT"))
print("MAIL_USE_TLS:", app.config.get("MAIL_USE_TLS"))
print("MAIL_USERNAME:", app.config.get("MAIL_USERNAME"))
print("MAIL_PASSWORD configured:", bool(app.config.get("MAIL_PASSWORD")))
print("MAIL_DEFAULT_SENDER:", app.config.get("MAIL_DEFAULT_SENDER"))
print("=================================")
mail = Mail(app)
print("MAIL EXTENSION REGISTERED:", app.extensions.get("mail"))

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

limiter=Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)
csrf=CSRFProtect(app)

db.init_app(app)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Email and Password are required", "danger")
            return render_template("login.html")

        user = User.query.filter_by(email=email).first()
        if user is None or not check_password_hash(user.password, password):
            flash("Invalid Email or Password", "danger")
            return render_template("login.html")

        session["user_id"] = user.id
        session["user_name"] = user.full_name
        session["user_email"] = user.email

        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        if not email:
            flash("Email address is required", "danger")
            return render_template("forgot_password.html")

        user = User.query.filter_by(email=email).first()

        if not user:
            flash(
                "If an account exists with this email, an OTP will be sent.",
                "info"
            )
            return render_template("forgot_password.html")

        otp = str(secrets.randbelow(900000) + 100000)

        otp_hash = generate_password_hash(otp)

        expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=10)

        try:

            PasswordReset.query.filter_by(
                user_id=user.id,
                used=False
            ).update({
                "used": True
            })

            reset = PasswordReset(
                user_id=user.id,
                otp_hash=otp_hash,
                expires_at=expires_at,
                attempts=0,
                used=False
            )

            db.session.add(reset)
            db.session.commit()

            message = Message(
                subject="SentinelMail Password Reset OTP",
                recipients=[user.email],
                body=f"""Hello {user.full_name},

We received a request to reset your SentinelMail password.

Your OTP is:

{otp}

This OTP will expire in 10 minutes.

If you did not request a password reset, please ignore this email.

Regards,
SentinelMail Security Team
"""
            )

            mail.send(message)

            session["reset_user_id"] = user.id
            session["reset_id"] = reset.id

            flash(
                "OTP has been sent to your registered email address.",
                "success"
            )

            return redirect(url_for("verify_otp"))

        except Exception as e:

            print("================================")
            print("EMAIL ERROR:", repr(e))
            print("================================")

            db.session.rollback()

            if "reset" in locals() and reset.id is not None:
                try:
                    db.session.delete(reset)
                    db.session.commit()
                except Exception:
                    db.session.rollback()

            flash(
                "Unable to send OTP email. Please try again.",
                "danger"
            )

            return render_template("forgot_password.html")

    return render_template("forgot_password.html")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    if "reset_user_id" not in session or "reset_id" not in session:
        return redirect(url_for("forgot_password"))

    reset = PasswordReset.query.filter_by(
        id=session["reset_id"],
        user_id=session["reset_user_id"],
        used=False
    ).first()

    if not reset:
        session.pop("reset_user_id", None)
        session.pop("reset_id", None)

        flash("Invalid or expired password reset request.", "danger")
        return redirect(url_for("forgot_password"))

    if datetime.utcnow() > reset.expires_at:
        reset.used = True
        db.session.commit()

        session.pop("reset_user_id", None)
        session.pop("reset_id", None)

        flash("OTP has expired. Please request a new one.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":

        otp = request.form.get("otp", "").strip()

        if not otp:
            flash("Please enter the OTP.", "danger")
            return render_template("verify_otp.html")

        if not otp.isdigit() or len(otp) != 6:
            flash("OTP must be a 6-digit number.", "danger")
            return render_template("verify_otp.html")

        if reset.attempts >= 5:
            reset.used = True
            db.session.commit()

            session.pop("reset_user_id", None)
            session.pop("reset_id", None)

            flash(
                "Too many incorrect attempts. Please request a new OTP.",
                "danger"
            )

            return redirect(url_for("forgot_password"))

        reset.attempts += 1

        if not check_password_hash(reset.otp_hash, otp):

            db.session.commit()

            remaining = 5 - reset.attempts

            if remaining > 0:
                flash(
                    f"Incorrect OTP. {remaining} attempt(s) remaining.",
                    "danger"
                )
            else:
                reset.used = True
                db.session.commit()

                session.pop("reset_user_id", None)
                session.pop("reset_id", None)

                flash(
                    "Too many incorrect attempts. Please request a new OTP.",
                    "danger"
                )

                return redirect(url_for("forgot_password"))

            return render_template("verify_otp.html")

        reset.used = True
        db.session.commit()

        session["otp_verified"] = True

        return redirect(url_for("reset_password"))

    return render_template("verify_otp.html")

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    # User must have successfully verified an OTP
    if "reset_user_id" not in session:
        flash("Please request a password reset first.", "danger")
        return redirect(url_for("forgot_password"))

    user_id = session["reset_user_id"]

    user = User.query.get(user_id)

    if not user:
        session.pop("reset_user_id", None)
        session.pop("reset_id", None)

        flash("Invalid password reset request.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":

        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash(
                "Password must be at least 8 characters long.",
                "danger"
            )
            return render_template("reset_password.html")

        if not re.search(r"[A-Z]", password):
            flash(
                "Password must contain at least one uppercase letter.",
                "danger"
            )
            return render_template("reset_password.html")

        if not re.search(r"[a-z]", password):
            flash(
                "Password must contain at least one lowercase letter.",
                "danger"
            )
            return render_template("reset_password.html")

        if not re.search(r"\d", password):
            flash(
                "Password must contain at least one number.",
                "danger"
            )
            return render_template("reset_password.html")

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", password):
            flash(
                "Password must contain at least one special character.",
                "danger"
            )
            return render_template("reset_password.html")

        if password != confirm_password:
            flash(
                "Passwords do not match.",
                "danger"
            )
            return render_template("reset_password.html")

        user.password = generate_password_hash(password)

        db.session.commit()

        session.pop("reset_user_id", None)
        session.pop("reset_id", None)

        flash(
            "Your password has been reset successfully. Please log in.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("reset_password.html")

@app.route("/test-email")
def test_email():

    msg = Message(
        subject="SentinelMail Email Test",
        recipients=[os.environ.get("MAIL_USERNAME")]
    )

    msg.body = """
Hello!

This is a test email from SentinelMail.

If you received this message, email delivery is working correctly.

SentinelMail
"""

    mail.send(msg)

    return "Test email sent successfully!"

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        if not full_name:
            flash("Full name is required", "danger")
            return render_template("register.html")
        if len(full_name) < 2 or len(full_name) > 100:
            flash("Full name must be between 2 and 100 characters")
            return render_template("register.html")

        email_pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"

        if not re.match(email_pattern, email):
            flash("Please enter a valid email address", "danger")
            return render_template("register.html")
        if len(password) <8:
            flash("Password must be at least 8 characters long", "danger")
            return render_template("register.html")
        if not re.search(r"[A-Z]", password):
            flash("Password must contain at least one uppercase letter", "danger")
            return render_template("register.html")
        if not  re.search(r"[a-z]", password):
            flash("Password must contain at least one lowercase letter", "danger")
            return render_template("register.html")
        if not  re.search(r"\d", password):
            flash("Password must contain at least one number", "danger")
            return render_template("register.html")
        if not  re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", password):
            flash("Password must contain at least one special character", "danger" )
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return render_template("register.html")

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash("Email already registered", "danger")
            return render_template("register.html")

        hashed_password = generate_password_hash(password)

        new_user = User(
            full_name=full_name,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    scans = ScanHistory.query.filter_by(
        user_id=session["user_id"]
    ).all()

    total_scans = len(scans)

    safe_count = sum(
        1 for scan in scans if scan.result == "Safe"
    )

    phishing_count = sum(
        1 for scan in scans if scan.result == "Phishing"
    )

    return render_template(
        "dashboard.html",
        scans=scans,
        total_scans=total_scans,
        safe_count=safe_count,
        phishing_count=phishing_count
    )
@app.route("/analyze", methods=["GET", "POST"])
def analyze():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        email_text = request.form.get("email_text", "").strip()

        if not email_text:
            flash("Please enter an email.", "danger")
            return render_template("analyze.html")

        result, phishing_probability, safe_probability = predict_email(
            email_text
        )        

        sender_match = re.search(
            r"From:\s*.*?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
            email_text,
            re.IGNORECASE
        )

        if sender_match:
            sender = sender_match.group(1)
        else:
            sender = ""



        url_analysis = analyze_email_urls(email_text)

        url_risk_score = 0
        url_indicators = []

        for url_result in url_analysis["urls"]:

            url_risk_score += url_result.get(
                "risk_score",
                0
            )

            url_indicators.extend(
                url_result.get(
                    "indicators",
                    []
                )
            )

        url_result_for_score = {
            "risk_score": min(url_risk_score, 8),
            "indicators": url_indicators
        }

        keyword_result = analyze_keywords(email_text)

        reply_to_match = re.search(
            r"Reply-To:\s*.*?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
            email_text,
            re.IGNORECASE
        )

        return_path_match = re.search(
            r"Return-Path:\s*.*?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
            email_text,
            re.IGNORECASE
        )

        spf_match = re.search(
            r"SPF:\s*(pass|fail|softfail)",
            email_text,
            re.IGNORECASE
        )

        dkim_match = re.search(
            r"DKIM:\s*(pass|fail)",
            email_text,
            re.IGNORECASE
        )

        dmarc_match = re.search(
            r"DMARC:\s*(pass|fail)",
            email_text,
            re.IGNORECASE
        )

        header_data = {
            "from": sender,
            "reply_to": reply_to_match.group(1)
                if reply_to_match else "",
            "return_path": return_path_match.group(1)
                if return_path_match else "",
            "spf": spf_match.group(1).lower()
                if spf_match else "",
            "dkim": dkim_match.group(1).lower()
                if dkim_match else "",
            "dmarc": dmarc_match.group(1).lower()
                if dmarc_match else ""
        }

        header_result = analyze_headers(header_data)

        if sender:

            sender_result = analyze_sender(sender)

        else:

            sender_result = {
                "risk_score": 0,
                "indicators": []
            }

        cybersecurity_result = calculate_threat_score(
            url_result_for_score,
            keyword_result,
            header_result,
            sender_result
        )

        new_scan = ScanHistory(
            user_id=session["user_id"],
            email_text=email_text,
            result=result,
            phishing_probability=float(phishing_probability),
            safe_probability=float(safe_probability)
        )

        db.session.add(new_scan)
        db.session.commit()

        session[f"cyber_{new_scan.id}"] = cybersecurity_result

        session[f"sender_{new_scan.id}"] = sender

        print("\n==============================")
        print("SENTINELMAIL ANALYSIS")
        print("==============================")

        print(
            "AI Result:",
            result
        )

        print(
            "AI Phishing Probability:",
            round(phishing_probability * 100, 2),
            "%"
        )

        print(
            "Cybersecurity Threat Score:",
            cybersecurity_result["threat_score"]
        )

        print(
            "Cybersecurity Threat Level:",
            cybersecurity_result["threat_level"]
        )

        print(
            "Module Scores:",
            cybersecurity_result["module_scores"]
        )

        print("Indicators:")

        for indicator in cybersecurity_result["indicators"]:
            print("-", indicator)

        print("==============================")

        return redirect(
            url_for(
                "result",
                scan_id=new_scan.id
            )
        )

    return render_template("analyze.html")

@app.route("/result/<int:scan_id>")
def result(scan_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    scan = ScanHistory.query.filter_by(
        id=scan_id,
        user_id=session["user_id"]
    ).first()

    if scan is None:
        return "Scan not found", 404

    cybersecurity_result = session.get(
        f"cyber_{scan_id}",
        {
            "threat_score": 0,
            "threat_level": "LOW",
            "module_scores": {
                "url": 0,
                "keyword": 0,
                "header": 0,
                "sender": 0
            },
            "indicators": []
        }
    )

    sender = session.get(
        f"sender_{scan_id}",
        "Unknown"
    )

    if (
        scan.result=="Phishing"
        and cybersecurity_result["threat_score"]<25
    ):
        display_result="Suspicious"
    else:
        display_result=scan.result

    return render_template(
        "result.html",

        result=scan.result,
        display_result=display_result,
        phishing_probability=scan.phishing_probability,
        safe_probability=scan.safe_probability,

        email_text=scan.email_text,
        sender=sender,

        cybersecurity=cybersecurity_result,
        threat_score=cybersecurity_result["threat_score"],
        threat_level=cybersecurity_result["threat_level"],
        module_scores=cybersecurity_result["module_scores"],
        indicators=cybersecurity_result["indicators"]
    )

@app.route("/history")
def history():
    if "user_id" not in session:
        return redirect(url_for("login"))
    scans= ScanHistory.query.filter_by(
        user_id=session["user_id"]).order_by(
            ScanHistory.created_at.desc()).all()
    total_scans= len(scans)
    safe_count=sum(
        1 for scan in scans if scan.result=="Safe"
    )
    phishing_count= sum(
        1 for scan in scans if scan.result=="Phishing"
    )
        
    return render_template("history.html",
                           scans=scans,
                           total_scans=total_scans,
                           safe_count=safe_count,
                           phishing_count=phishing_count)


@app.route("/profile")
def profile():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    scans = ScanHistory.query.filter_by(
        user_id=session["user_id"]
    ).all()

    total_scans = len(scans)

    phishing_count = sum(
        1 for scan in scans
        if scan.result == "Phishing"
    )

    return render_template(
        "profile.html",
        user=user,
        total_scans=total_scans,
        phishing_count=phishing_count
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run()