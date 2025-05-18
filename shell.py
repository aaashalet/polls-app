from app import app, db, User

with app.app_context():
    user = User.query.filter_by(username='soulboy228').first()
    if user:
        user.is_admin = True
        db.session.commit()
        print(f"User {user.username} is now admin.")
    else:
        print("User not found.")
