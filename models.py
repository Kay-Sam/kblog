from app import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, index=True)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(200))
    created = db.Column(db.DateTime, default=datetime.now)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100))
    reset_code = db.Column(db.String(10))
    reset_code_sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)  

    # One-to-Many relationship with Blog    
    comments = db.relationship('Comment', backref='user', lazy=True)
    blogs = db.relationship('Blog', back_populates='user', cascade="all, delete")

    def __repr__(self):
        return "<User {}>".format(self.username)
    
# CATEGORY MODEL
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    blogs = db.relationship('Blog', backref='category', lazy=True)


# TAGS ASSOCIATION TABLE
blog_tags = db.Table('blog_tags',
    db.Column('blog_id', db.Integer, db.ForeignKey('blog.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)

# TAG MODEL
class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True, nullable=False)

class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(200))  
    views = db.Column(db.Integer, default=0)
    date_published = db.Column(db.DateTime, default=datetime.now, nullable=False)


    # Foreign key relationship with User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_blog_user'), nullable=False)

    # Category relationship
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))

    # Tags many-to-many
    tags = db.relationship('Tag', secondary=blog_tags, backref=db.backref('blogs', lazy='dynamic'))
    
    # One-to-Many relationship with User
    user = db.relationship('User', back_populates='blogs')    
    comments = db.relationship('Comment', backref='blog', lazy=True, cascade='all, delete')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    blog_id = db.Column(db.Integer, db.ForeignKey('blog.id'))

    def __repr__(self):
        return "<Blog {}>".format(self.title)
