from datetime import timedelta
import hashlib
import os
from flask import flash, redirect, request, render_template, session, url_for, send_from_directory,abort
from flask_mail import Mail, Message
from app import app,db,mail
from models import Blog, User, Comment, Category, Tag
from auth import check_login
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from datetime import datetime
import random,string
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import func 

# Token serializer (used for email verification)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

s = URLSafeTimedSerializer(app.secret_key)


load_dotenv()

@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return dict(current_user=user)

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/')
@app.route('/page/<int:page>')
def home_page(page=1):
    per_page = 6
    blogs = Blog.query.order_by(Blog.date_published.desc()).paginate(page=page, per_page=per_page)

    recent_posts = Blog.query.order_by(Blog.date_published.desc()).limit(5).all()
    categories = Category.query.all()
    tags = Tag.query.all()

    return render_template(
        'index.html',
        blogs=blogs,
        recent_posts=recent_posts,
        categories=categories,
        tags=tags
    )

# @app.route('/page/<int:page>')
# def home_page(page=1):
#     current_user = None

#     if 'user_id' in session:
#         user_id = session['user_id']
#         current_user = User.query.get(user_id)

#     per_page = 6
#     blogs = Blog.query.order_by(Blog.date_published.desc()).paginate(page=page, per_page=per_page)

#     return render_template('index.html', current_user=current_user, blogs=blogs, session=session)


# @app.route('/')
# def home_page():
#     current_user = None  # Initialize as None

#     if 'user_id' in session:
#         user_id = session['user_id']
#         current_user = User.query.get(user_id)  # Fetch user from DB

#     blogs = Blog.query.order_by(Blog.date_published.desc()).all()
    
#     return render_template('index.html', current_user=current_user, blogs=blogs, session=session)


@app.route('/admin')
def admin_page():
   users=User.query.all()
   return render_template('admin.html', users=users)

@app.route('/signup')
def sign_up():
    return render_template('signup.html')

@app.route('/do-signup', methods=['POST'])
def do_signup():
    username = request.form.get('username')
    email = request.form.get('email')
    phone = request.form.get('phone')
    password = request.form.get('password')
    confirmpassword = request.form.get('confirmpassword')

    # Validation
    if username == '':
        flash('Please enter your username!')
        return redirect(url_for('sign_up'))
    elif email == '':
        flash('Please enter your email')
        return redirect(url_for('sign_up'))
    existing_user = User.query.filter(func.lower(User.username) == username.lower()).first()
    if existing_user:
        flash('Username already exists. Please use a different username.', 'error')
        return redirect(url_for('sign_up'))
    
    if User.query.filter_by(email=email).first():
        flash('Email already exists. Please use a different email.', 'error')
        return redirect(url_for('sign_up'))
    elif phone == '':
        flash('Please enter your Phone Number')
        return redirect(url_for('sign_up'))
    elif password != confirmpassword:
        flash('Passwords do not match')
        return redirect(url_for('sign_up'))

    # Hash password
    pw = hashlib.sha256(password.encode()).hexdigest()

    # Create new user
    new_user = User(username=username, email=email, phone=phone, password_hash=pw, is_verified=False)
    db.session.add(new_user)
    db.session.commit()

    # Create verification token
    token = serializer.dumps(email, salt='email-confirm')

    # Create confirmation URL
    confirm_url = url_for('verify_email', token=token, _external=True)

    # Send email
    msg = Message(
        subject='Verify Your Email',
        recipients=[email],
        body=f"""Hi {username},

Thank you for registering!

Click the link below to verify your email and activate your account:

{confirm_url}

This link will expire in 30 minutes.

If you did not sign up, please ignore this email."""
    )
    mail.send(msg)

    flash('A verification email has been sent. Please check your inbox.', 'info')
    return redirect(url_for('login_page'))

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=1800)  # 30 minutes
    except Exception:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login_page'))

    user = User.query.filter_by(email=email).first()
    if user is None:
        flash('User not found.', 'danger')
        return redirect(url_for('sign_up'))

    if user.is_verified:
        flash('Account already verified. Please log in.', 'info')
    else:
        user.is_verified = True
        db.session.commit()
        flash('Email verified successfully! You can now log in.', 'success')

    return redirect(url_for('login_page'))

@app.route('/process-login', methods=['POST'])
def process_login():
   email = request.form.get('email')
   password = request.form.get('password')
   if email == '':
      flash('Please enter email.', 'error')
      return redirect(url_for('login_page'))
   # find user in database
   correct_user = User.query.filter(User.email == email).first()
   if correct_user is None:
      flash('Invalid email or password', 'error')
      return redirect(url_for('login_page'))
      # Check if user is verified
   if not correct_user.is_verified:
        flash('Please verify your email before logging in.', 'error')
        return redirect(url_for('login_page'))
   # hash password
   
   pw = hashlib.sha256(password.encode()).hexdigest()
   # check if password is the same
   if correct_user.password_hash != pw:
      flash('Invalid email or password', 'error')
      return redirect(url_for('login_page'))
   # login is correct 
   session['user_id'] = correct_user.id  # Instead of session['id']
   resp = redirect(url_for('home_page'))
   # set cookie
   resp.set_cookie('id', str(correct_user.id), max_age=timedelta(days=5))
   resp.set_cookie('p_hash', pw, max_age=timedelta(days=5))
   return resp



@app.route('/blog')
@app.route('/blog/page/<int:page>')
def blog(page=1):
    profile = check_login()


 
    per_page = 6
    blogs = Blog.query.order_by(Blog.date_published.desc()).paginate(page=page, per_page=per_page)
    recent_posts = Blog.query.order_by(Blog.date_published.desc()).limit(5).all()
    categories = Category.query.all()
    tags = Tag.query.all()

    return render_template(
            'index.html',current_user=profile,
            blogs=blogs,
            recent_posts=recent_posts,
            categories=categories,
            tags=tags, session=session
        )


# @app.route('/blog')
# def blog():
#    #  users = User.query.all()  # Fetch all users
#    #  blogs = Blog.query.order_by(Blog.date_published.desc()).all()  # Get all blogs
#    #  return render_template('blog.html', users=users, blogs=blogs)

#     profile = check_login()    
#     blogs = Blog.query.order_by(Blog.date_published.desc()).all()  # Newest first
#     return render_template('index.html', current_user=profile, blogs=blogs, session=session)
@app.route('/add')
def add_post():
    users = User.query.all()

    current_user = None
    if 'user_id' in session:
        current_user = User.query.get(session['user_id'])

    categories = Category.query.order_by(Category.name).all()

    return render_template('blog.html',
                           users=users,
                           current_user=current_user,
                           categories=categories)

# @app.route('/add')
# def add_post():
#     users = User.query.all()  # Fetch all users
    
#     # Check if a user is logged in
#     current_user = None
#     if 'user_id' in session:
#         current_user = User.query.get(session['user_id'])

#     return render_template('blog.html', users=users, current_user=current_user)  
@app.route('/login')
def login_page():
    return render_template ('login.html')

@app.route('/blog', methods=['GET', 'POST'])
def create_blog():
    if 'user_id' not in session:
        flash('You need to be logged in to create a blog.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category_id = request.form.get('category_id')
        tag_input = request.form.get('tags', '')
        user_id = session['user_id']

        # Handle image upload
        image = request.files.get('image')
        image_filename = None
        if image and image.filename != '':
            filename = secure_filename(image.filename)
            image_path = os.path.join('static/uploads', filename)  # Save to /static/uploads/
            image.save(image_path)
            image_filename = filename

        # Create blog post
        new_blog = Blog(
            title=title,
            description=description,
            image_filename=image_filename,
            category_id=category_id,
            user_id=user_id
        )

        # Process tags
        tag_names = [t.strip().lower() for t in tag_input.split(',') if t.strip()]
        tags = []
        for tag_name in tag_names:
            existing_tag = Tag.query.filter_by(name=tag_name).first()
            if existing_tag:
                tags.append(existing_tag)
            else:
                new_tag = Tag(name=tag_name)
                db.session.add(new_tag)
                tags.append(new_tag)

        new_blog.tags = tags
        db.session.add(new_blog)
        db.session.commit()

        flash('Blog created successfully!', 'success')
        return redirect(url_for('home_page'))

    # For GET request
    categories = Category.query.order_by(Category.name).all()
    return render_template('blog.html', categories=categories)





@app.route('/edit-blog/<int:blog_id>', methods=['GET', 'POST'])
def edit_blog(blog_id):
    if 'user_id' not in session:  # Ensure user is logged in
        flash('You need to log in to edit a post.', 'error')
        return redirect(url_for('login_page')) 

    current_user = check_login()  # Get the logged-in user

    if not current_user:
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login_page'))

    blog = Blog.query.get_or_404(blog_id)

    # Check if the logged-in user is the owner of the post
    if blog.user_id != current_user.id:
        abort(403)  # Forbidden access if the user is not the owner

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')

        # Handling the file upload
        image_file = request.files.get('image')

        if not title or not description:
            flash('Title and description are required.', 'error')
        else:
            # Update blog post
            blog.title = title
            blog.description = description

            # If a new image is uploaded, save it
            if image_file:
                # Ensure it's an allowed file type (e.g., jpg, png, gif)
                if image_file.filename.lower().endswith(('jpg', 'jpeg', 'png', 'gif')):
                    image_filename = secure_filename(image_file.filename)
                    image_file.save(os.path.join('static/uploads', image_filename))
                    blog.image_filename = image_filename  # ✅ use the same name everywhere
                else:
                    flash('Invalid image file type. Please upload a .jpg, .jpeg, .png, or .gif file.', 'error')

            db.session.commit()
            flash('Post updated successfully!', 'success')
            return redirect(url_for('home_page'))

    return render_template('edit_blog.html', blog=blog, current_user=current_user)


 
@app.route('/delete-blog/<int:blog_id>', methods=['POST'])
def delete_blog(blog_id):
    if 'user_id' not in session:
        flash('You need to log in to delete a post.', 'error')
        return redirect(url_for('login'))

    blog = Blog.query.get_or_404(blog_id)  # Fetch the blog, return 404 if not found

    # Check if the logged-in user is the owner of the post
    if blog.user_id != session['user_id']:
        abort(403)  # Forbidden if the user is not the owner

    # If the blog post has an image, delete the image from the filesystem
    if blog.image_filename:
        image_path = os.path.join('static', 'uploads', blog.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)  # Delete the image file

    # Delete the blog post from the database
    db.session.delete(blog)  
    db.session.commit()  

    flash('Blog post deleted successfully!', 'success')
    return redirect(url_for('home_page'))

@app.route('/my_posts')
@app.route('/my_posts/page/<int:page>')
def my_posts(page=1):
    if 'user_id' not in session:
        flash('You need to log in first!', 'warning')
        return redirect(url_for('login'))

    profile = check_login()

    per_page = 6
    user_posts = Blog.query.filter_by(user_id=session['user_id'])\
        .order_by(Blog.date_published.desc())\
        .paginate(page=page, per_page=per_page)
    recent_posts = Blog.query.order_by(Blog.date_published.desc()).limit(5).all()
    categories = Category.query.all()
    tags = Tag.query.all()

    return render_template(
        'my_posts.html', blogs=user_posts, current_user=profile,
        recent_posts=recent_posts,
        categories=categories,
        tags=tags
    )



@app.route('/blog/<int:blog_id>')
def view_blog(blog_id):
    blog = Blog.query.get_or_404(blog_id)

    # Handle None case
    if blog.views is None:
        blog.views = 1
    else:
        blog.views += 1

    db.session.commit()

    comments = Comment.query.filter_by(blog_id=blog.id).order_by(Comment.date_posted.desc()).all()
    user_id = session.get('user_id')
    recent_posts = Blog.query.order_by(Blog.date_published.desc()).limit(5).all()
    categories = Category.query.all()
    tags = Tag.query.all()

    return render_template('view_blog.html', blog=blog, comments=comments, user_id=user_id,
        recent_posts=recent_posts,
        categories=categories,
        tags=tags
    )




@app.route('/blog/<int:blog_id>/comment', methods=['POST'])
def add_comment(blog_id):
    if 'user_id' not in session:
        flash("You must be logged in to comment.")
        return redirect(url_for('login_page'))

    content = request.form['content']
    user_id = session['user_id']

    comment = Comment(content=content, user_id=user_id, blog_id=blog_id)
    db.session.add(comment)
    db.session.commit()

    return redirect(url_for('view_blog', blog_id=blog_id))


@app.route('/logout')
def logout():
   # clear session
   session.pop('user_id')
   # expire cookies
   resp = redirect(url_for('login_page'))
   resp.set_cookie('user_id', expires=0)
   resp.set_cookie('p_hash', expires=0)
   flash("You are Logged Out!")
   return resp
   # return render_template('login.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('You need to log in to view your profile.', 'error')
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])

    if not current_user:
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login'))

    post_count = Blog.query.filter_by(user_id=current_user.id).count()
    total_views = db.session.query(db.func.sum(Blog.views)).filter_by(user_id=current_user.id).scalar() or 0

    #  This is the correct place
    user_blogs = Blog.query.filter_by(user_id=current_user.id).order_by(Blog.date_published.desc()).all()

    return render_template('profile.html',
                           current_user=current_user,
                           post_count=post_count,
                           total_views=total_views,
                           user_blogs=user_blogs)



@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        flash('You need to log in to access settings.', 'error')
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_email = request.form.get('email')

        if new_username:
            existing_user = User.query.filter(
                db.func.lower(User.username) == new_username.lower(),
                User.id != current_user.id
            ).first()
            if existing_user:
                flash('Username already taken.', 'error')
                return redirect(url_for('settings'))
            current_user.username = new_username

        if new_email and new_email.lower() != current_user.email.lower():
            existing_email = User.query.filter(
                db.func.lower(User.email) == new_email.lower(),
                User.id != current_user.id
            ).first()
            if existing_email:
                flash('Email already registered.', 'error')
                return redirect(url_for('settings'))

            # Generate token with new email and user id (to verify user)
            token = serializer.dumps({'user_id': current_user.id, 'new_email': new_email}, salt='email-change')

            verify_url = url_for('confirm_email_change', token=token, _external=True)

            msg = Message('Confirm your email change',
                          sender='your_email@example.com',
                          recipients=[new_email])
            msg.body = f'Please click the link to confirm your new email address: {verify_url}'
            mail.send(msg)

            flash('A confirmation email has been sent to your new email address. Please check your inbox.', 'info')

            # Commit username changes only here (email changes after confirmation)
            db.session.commit()
            return redirect(url_for('settings'))

        # If email not changed, just commit username changes and redirect
        db.session.commit()
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('settings.html', current_user=current_user)


@app.route('/confirm-email-change/<token>')
def confirm_email_change(token):
    try:
        data = serializer.loads(token, salt='email-change', max_age=3600)  # Expires in 1 hour
        user_id = data.get('user_id')
        new_email = data.get('new_email')
    except Exception:
        flash('The confirmation link is invalid or expired.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    # Double-check if new_email is taken by another user (very unlikely but safe)
    existing_email = User.query.filter(
        db.func.lower(User.email) == new_email.lower(),
        User.id != user.id
    ).first()
    if existing_email:
        flash('Email already registered by another user.', 'error')
        return redirect(url_for('login'))

    # Update email and commit
    user.email = new_email
    db.session.commit()

    flash('Your email has been updated successfully. Please log in with your new email.', 'success')
    return redirect(url_for('login'))


@app.route('/search')
def search():
    query = request.args.get('q')
    results = Blog.query.filter(Blog.title.ilike(f'%{query}%') | Blog.description.ilike(f'%{query}%')).all()
    return render_template('search_results.html', results=results, query=query)

@app.route('/category/<int:category_id>')
def category_blogs(category_id):
    category = Category.query.get_or_404(category_id)
    blogs = Blog.query.filter_by(category_id=category.id).order_by(Blog.date_published.desc()).all()
    return render_template('category_blogs.html', blogs=blogs, category=category)

@app.route('/tag/<int:tag_id>')
def tag_blogs(tag_id):
    tag = Tag.query.get_or_404(tag_id)
    # blogs = tag.blogs.order_by(Blog.date_published.desc()).all()
    blogs = Blog.query.filter(Blog.tags.any(Tag.id == tag.id)).order_by(Blog.date_published.desc()).all()
    return render_template('tag_blogs.html', blogs=blogs, tag=tag)

@app.route('/seed_categories')
def seed_categories():
    category_names = ['Technology', 'Health', 'Lifestyle', 'Education', 'Travel','Food']
    for name in category_names:
        if not Category.query.filter_by(name=name).first():
            db.session.add(Category(name=name))
    db.session.commit()
    return 'Categories seeded successfully.'

# Forgot password
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            code = str(random.randint(100000, 999999))
            session['reset_code'] = code
            session['reset_email'] = email
            session['reset_code_time'] = datetime.utcnow().timestamp()

            msg = Message(
                'Your Reset Code',
                recipients=[email],
                body=f"""Your reset code is: {code}

This code will expire in 1 hour. If you did not request this, please ignore this message."""
            )
            mail.send(msg)

            flash('Reset code sent. Check your email. Code expires in 1 hour.', 'info')
            return redirect(url_for('enter_code'))
        else:
            flash('Email not found.', 'danger')
    return render_template('forgot_password.html')

# Enter reset code
@app.route('/enter-code', methods=['GET', 'POST'])
def enter_code():
    if request.method == 'POST':
        entered_code = request.form['code']
        code_time = session.get('reset_code_time')

        if code_time and datetime.utcnow().timestamp() - code_time > 3600:
            session.pop('reset_code', None)
            session.pop('reset_code_time', None)
            session.pop('reset_email', None)
            flash('Reset code expired. Try again.', 'danger')
            return redirect(url_for('forgot_password'))

        if entered_code == session.get('reset_code'):
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid reset code.', 'danger')
    return render_template('enter_code.html')    

# Reset password
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        flash('Session expired. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm']
        email = session.get('reset_email')
        user = User.query.filter_by(email=email).first()

        # Check if passwords match
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html')

        # Password strength validation
        if (
            len(new_password) < 6
        ):
            flash('Password must be at least 6 characters long', 'warning')
            return render_template('reset_password.html')

        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            session.clear()
            flash('Password reset successful. Please log in.', 'success')
            return redirect(url_for('login'))

        flash('User not found.', 'danger')

    return render_template('reset_password.html')

@app.route('/resend', methods=['POST'])
def resend():
    return render_template('resend_reset.html')

@app.route('/resend-reset', methods=['GET', 'POST'])
def resend_reset():
    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()

    if not user:
        flash("Email not found", "danger")
        return redirect(url_for('forgot_password'))

    # Optional: Prevent resending if already verified (for verification use cases)
    if user.is_verified:
        flash("Account already verified", "info")
        return redirect(url_for('login'))

    # Rate limit resend: Only allow every 2 minutes
    now = datetime.utcnow()
    if user.reset_code_sent_at and (now - user.reset_code_sent_at).seconds < 120:
        flash("Please wait before resending the code.", "warning")
        return redirect(url_for('forgot_password'))

    # Invalidate old code by generating a new one
    new_code = ''.join(random.choices(string.digits, k=6))
    user.reset_code = new_code
    user.reset_code_sent_at = now
    db.session.commit()

    # Send new reset code email
    msg = Message("Your New Reset Code", recipients=[user.email])
    msg.body = f"Your new reset code is: {new_code}"
    try:
        mail.send(msg)
        flash("New reset code sent to your email.", "success")
        return redirect(url_for('verify_reset'))
    except Exception as e:
        flash("Failed to send email. Please try again later.", "danger")
        return redirect(url_for('forgot_password'))