from flask import session, request
from models import User

def check_login():
    # Check if user_id is in session
    user_id = session.get('user_id')  # Use .get() to avoid KeyError

    # If not in session, try retrieving from cookies
    if user_id is None:
        user_id = request.cookies.get('id')

    # Ensure user_id is valid
    if user_id:
        current_user = User.query.filter_by(id=user_id).first()
        return current_user
    return None
