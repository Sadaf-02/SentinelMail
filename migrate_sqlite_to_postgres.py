import sqlite3
import runpy

# ==========================================
# 1. Load SentinelMail Flask app + database
# ==========================================

app_data = runpy.run_path("app.py")

app = app_data["app"]
db = app_data["db"]
User = app_data["User"]
ScanHistory = app_data["ScanHistory"]

# ==========================================
# 2. Read existing SQLite database
# ==========================================

sqlite_connection = sqlite3.connect("instance/database.db")
sqlite_connection.row_factory = sqlite3.Row

sqlite_cursor = sqlite_connection.cursor()

users = sqlite_cursor.execute(
    "SELECT * FROM users"
).fetchall()

scans = sqlite_cursor.execute(
    "SELECT * FROM scan_history"
).fetchall()

print("SQLite data found:")
print("Users:", len(users))
print("Scans:", len(scans))

# ==========================================
# 3. Insert into PostgreSQL
# ==========================================

with app.app_context():

    # ---- Users ----

    for row in users:

        existing_user = db.session.get(
            User,
            row["id"]
        )

        if existing_user:
            print(
                f"User {row['id']} already exists - skipping"
            )
            continue

        user = User(
            id=row["id"],
            full_name=row["full_name"],
            email=row["email"],
            password=row["password"],
            created_at=row["created_at"]
        )

        db.session.add(user)

    db.session.commit()

    # ---- Scan History ----

    for row in scans:

        existing_scan = db.session.get(
            ScanHistory,
            row["id"]
        )

        if existing_scan:
            print(
                f"Scan {row['id']} already exists - skipping"
            )
            continue

        scan = ScanHistory(
            id=row["id"],
            user_id=row["user_id"],
            email_text=row["email_text"],
            result=row["result"],
            phishing_probability=row["phishing_probability"],
            safe_probability=row["safe_probability"],
            created_at=row["created_at"]
        )

        db.session.add(scan)

    db.session.commit()

print()
print("================================")
print("MIGRATION COMPLETED")
print("================================")

sqlite_connection.close()