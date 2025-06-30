from app import db, User

# Update the username
try:
    user = User.query.filter_by(username='Steve Zhuo').first()
    if user:
        user.username = 'steve.zhuo'
        db.session.commit()
        print("Username updated successfully!")
    else:
        print("No user found with username 'Steve Zhuo'")
except Exception as e:
    print("Error updating username:", str(e))
