from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	public_id = db.Column(db.String(50), unique=True)
	username = db.Column(db.String(50), unique=True)
	email = db.Column(db.String(80), unique=True)
	password = db.Column(db.String(120),unique=True)

	def __init__(self, username, email, password, admin):
		self.username = username
		self.email= email
		self.password = generate_password_hash(password)

	def __repr__(self):
		return '<User %r>' % self.username

class ShoppingList(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(50))
	user_id = db.Column (db.Integer)
	user =  db.relationship('User', backref='shopping_list', lazy='dynamic')

	def __init__(self, name, user_id):
		self.name = name
		self.user_id = user_id

	def __repr__(self):
		return '<Shopping List: %r>' % self.name

class ShoppingItem(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(50))
	quantity = db.Column(db.Integer)
	bought = db.Column(db.String(80))
	shopping_list_id = db.Column(db.Integer, db.ForeignKey('shopping_list.id'))
	shopping_list = db.relationship('ShoppingList', backref='shopping_item', lazy='dynamic')

	def __init__(self, name, quantity, bought):
		self.name = name
		self.quantity = quantity
		self.bought = bought

	def __repr__(self):
		return '<Shopping Item %r>' % self.name
