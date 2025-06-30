from app import db, User

# Create the role column if it doesn't exist
try:
    # Add the role column with default value 'user'
    db.engine.execute("ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT 'user' NOT NULL")
    print("Role column added to user table")
except Exception as e:
    print("Role column already exists or other error occurred:", str(e))

# Set admin role for user with username 'admin'
try:
    admin_user = User.query.filter_by(username='admin').first()
    if admin_user:
        admin_user.role = 'admin'
        db.session.commit()
        print("Admin role set for user 'admin'")
    else:
        print("No user found with username 'admin'")
except Exception as e:
    print("Error setting admin role:", str(e))
