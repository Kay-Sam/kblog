CREATE TABLE alembic_version (
    version_num VARCHAR(32) PRIMARY KEY
);

INSERT INTO alembic_version VALUES ('276bee1d81e3');

CREATE TABLE category (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

INSERT INTO category (id, name) VALUES
(1,'Technology'),
(2,'Health'),
(3,'Lifestyle'),
(4,'Education'),
(5,'Travel'),
(6,'Food');

CREATE TABLE tag (
    id SERIAL PRIMARY KEY,
    name VARCHAR(30) UNIQUE NOT NULL
);

INSERT INTO tag (id, name) VALUES
(1,'flask'),
(2,'web development'),
(3,'mobile'),
(4,'react-native'),
(5,'flutter');

CREATE TABLE "user" (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(200),
    phone VARCHAR(20),
    password_hash VARCHAR(200),
    created TIMESTAMP,
    is_verified BOOLEAN,
    verification_token VARCHAR(100),
    reset_code VARCHAR(10),
    reset_code_sent_at TIMESTAMP
);

INSERT INTO "user" (id, username, email, phone, password_hash, created, is_verified, verification_token, reset_code, reset_code_sent_at)
VALUES (1,'Sammy','kayodesamuel2588@gmail.com','09079459440','ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f','2025-08-08 15:08:51.388823',true,NULL,NULL,'2025-08-08 14:08:51.388823');

CREATE TABLE blog (
    id SERIAL PRIMARY KEY,
    title VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    image_filename VARCHAR(200),
    views INTEGER,
    date_published TIMESTAMP NOT NULL,
    user_id INTEGER NOT NULL REFERENCES "user" (id),
    category_id INTEGER REFERENCES category (id)
);

INSERT INTO blog (id, title, description, image_filename, views, date_published, user_id, category_id)
VALUES
(1,'Getting Started with Flask for Web Development',replace(replace('Flask is one of the most popular micro web frameworks in Python...','\r',char(13)),'\n',char(10)),'download_6.png',17,'2025-08-08 15:13:33.817799',1,1),
(2,'React Native vs Flutter: Which is Best for Mobile App Development?',replace(replace('In today’s fast-paced digital world, mobile apps have become an essential...','\r',char(13)),'\n',char(10)),'download_13.png',5,'2025-08-08 17:39:14.797486',1,1);

CREATE TABLE blog_tags (
    blog_id INTEGER REFERENCES blog (id),
    tag_id INTEGER REFERENCES tag (id)
);

INSERT INTO blog_tags (blog_id, tag_id) VALUES
(1,1),
(1,2),
(2,3),
(2,4),
(2,5);

CREATE TABLE comment (
    id SERIAL PRIMARY KEY,
    content TEXT NOT NULL,
    date_posted TIMESTAMP,
    user_id INTEGER REFERENCES "user" (id),
    blog_id INTEGER REFERENCES blog (id)
);

CREATE UNIQUE INDEX ix_user_email ON "user" (email);
CREATE INDEX ix_user_id ON "user" (id);
