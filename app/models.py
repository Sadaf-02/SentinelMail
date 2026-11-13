from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    full_name = db.Column(db.String(100), nullable=False)

    email = db.Column(db.String(120), unique=True, nullable=False)

    password = db.Column(db.String(255), nullable=False)

    created_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )

    def __repr__(self):
        return f"<User {self.email}>"


class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    email_text = db.Column(db.Text, nullable=False)

    result = db.Column(db.String(20), nullable=False)

    phishing_probability = db.Column(db.Float, nullable=False)

    safe_probability = db.Column(db.Float, nullable=False)

    created_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )

    def __repr__(self):
        return f"<ScanHistory {self.id} - User {self.user_id}>"


class PasswordReset(db.Model):
    __tablename__ = "password_resets"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    otp_hash = db.Column(
        db.String(255),
        nullable=False
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=False
    )

    attempts = db.Column(
        db.Integer,
        default=0,
        nullable=False
    )

    used = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )

    def __repr__(self):
        return f"<PasswordReset {self.id} - User {self.user_id}>"