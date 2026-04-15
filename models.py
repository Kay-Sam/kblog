from app import db
from datetime import datetime


# =========================
# USER MODEL
# =========================
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, index=True, nullable=False)

    phone = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(200), nullable=True)

    # OAuth / Auth system
    auth_provider = db.Column(db.String(50), default="email")  
    google_id = db.Column(db.String(200), unique=True, nullable=True)

    created = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)

    verification_token = db.Column(db.String(100), nullable=True)
    reset_code = db.Column(db.String(10), nullable=True)
    reset_code_sent_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    blogs = db.relationship(
        "Blog",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    comments = db.relationship(
        "Comment",
        backref="user",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<User {self.username}>"



# =========================
# CATEGORY MODEL
# =========================
class Category(db.Model):
    __tablename__ = "categories"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    blogs = db.relationship("Blog", backref="category", lazy=True)



# =========================
# TAG MODEL (MANY TO MANY)
# =========================
blog_tags = db.Table(
    "blog_tags",
    db.Column("blog_id", db.Integer, db.ForeignKey("blogs.id")),
    db.Column("tag_id", db.Integer, db.ForeignKey("tags.id"))
)


class Tag(db.Model):
    __tablename__ = "tags"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True, nullable=False)

    blogs = db.relationship(
        "Blog",
        secondary=blog_tags,
        back_populates="tags"
    )



# =========================
# BLOG MODEL
# =========================
class Blog(db.Model):
    __tablename__ = "blogs"

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(200), nullable=True)

    views = db.Column(db.Integer, default=0)
    date_published = db.Column(db.DateTime, default=datetime.utcnow)

    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey("categories.id"))

    # Relationships
    user = db.relationship("User", back_populates="blogs")

    tags = db.relationship(
        "Tag",
        secondary=blog_tags,
        back_populates="blogs"
    )

    comments = db.relationship(
        "Comment",
        backref="blog",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Blog {self.title}>"



# =========================
# COMMENT MODEL
# =========================
class Comment(db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)

    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    blog_id = db.Column(db.Integer, db.ForeignKey("blogs.id"))

    def __repr__(self):
        return f"<Comment {self.id}>"