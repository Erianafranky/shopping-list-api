from flask import Flask, request, jsonify, make_response
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from models import db, User, ShoppingList, ShoppingItem

app = Flask(__name__)
POSTGRES = {
	'user': 'postgres',
	'pw': 'postgres',
	'db': 'shoppinglistapi'
	'host': 'localhost'
	'port': '5432'

}
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
db.init_app(app)

app.config['SECRET_KEY'] = 'mysecretkey'


def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None

		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']

		if not token:
			return jsonify({'message;' :'Token is missing'}), 401

		try:
			data = jwt.decode(token, app.config['SECRET_KEY'])
			current_user = user.query.filter_by(public_id=data['public_id']).first()
		except:
			return jsonify({'message': 'Token is invalid!'}), 401

		return f(current_user, *args **kwargs)

	return decorated

@app.route('/user', methods=['GET'])
@token_required
def view_all_users(current_user):

	users = user.query.all()

	output = []

	for user in users:
		user_data = {}
		user_data['public_id'] = user.public_id
		user_data['username'] = user.username
		user_data['email'] = user.email
		user_data['password'] = user.password
		output.append(user_data)

	return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
def view_one_user(current_user, public_id):

	user = User.query.filter_by(public_id=public_id).first()

	if not user:
		return jsonify({'message' : 'No user found!'})

	user_data = {}
	user_data['public_id'] = user.public_id
	user_data['username'] = user.username
	user_data['email'] = user.email
	user_data['password'] = user.password

	return jsonify({'user' : user_data})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

	user = User.query.filter_by(public_id=public_id).first()

	if not user:
		return jsonify({'message' : 'No user found!'})

	db.session.delete(user)
	db.session.commit()

	return jsonify({'message' : 'The user has been deleted!'}) 


@app.route('/register', methods=['POST'])
@token_required
def create_account(current_user):
	data = request.get_json()
	user = user.query.filter_by(username=data['username']).first()

	if not user:
		return jsonify({'message' : 'User already exists!'})
	
	new_user = User(public_id=str(uuid.uuid4()), username=data['username'], email=data['email'], password=data['password'], admin=False)
	db.session.add(new_user)
	db.commit()
	return jsonify({'message' : 'You are registered and can login!'})


@app.route('/login')
def login():
	auth = request.authorization

	if not auth or not auth.username or not auth.password:
		return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
 
	user = User.query.filter_by(username=auth.username).first()

	if not user:
		return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

	if check_password_hash(user.password, auth.password):
		token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=50)}, app.config['SECRET_KEY'])
		return jsonify({'token' : token.decode('UTF-8')})

	return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


@app.route('/shoppinglist', methods=['POST'])
@token_required
def create_shopping_list(current_user):
	data = request.get_json()

	new_shopping_list = ShoppingList(text=data['text'],user_id=current_user.id)
	db.session.add(new_shopping_list)
	db.session.commit()

	return jsonify({'message' : "Shopping List created!"})


@app.route('/shoppinglist', methods=['GET'])
@token_required
def view_all_shopping_list(current_user):
	shopping_lists = ShoppingList.query.filter_by(user_id=current_user.id).all()

	output = []

	for shopping_list in shopping_lists:
		shopping_list_data = {}
		shopping_list_data['id'] = shopping_list.id
		shopping_list_data['name'] = shopping_list.name
		output.append(shopping_list_data)

	return jsonify({'shopping_lists' : output})


@app.route('/shoppinglist/<shoppinglist_id>', methods=['GET'])
@token_required
def view_one_shopping_list(current_user, shoppinglist_id):
	shopping_list = ShoppingList.query.filter_by(id=shoppinglist_id, user_id=current_user.id).first()

	if not shopping_list:
		return jsonify({'message' : 'No shoppinglistfound!'})

	shopping_list_data = {}
	shopping_list_data['id'] = shopping_list.id
	shopping_list_data['name'] = shopping_list.name

	return jsonify(shopping_list_data)


@app.route('/shoppinglist/<shoppinglist_id>', methods=['PUT'])
@token_required
def update_shopping_list(current_user,shoppinglist_id):
	shopping_list = ShoppingList.query.filter_by(id=shoppinglist_id, user_id=current_user.id).first()

	if not shopping_list:
		return jsonify({'message' : 'No shoppinglist found!'})

	data = request.get_json()
	if 'name' in json.dumps(data):
		shopping_list.name = data['name']

		db.session.commit()

		return jsonify({'message' : 'Shopping List updated!'})


@app.route('/shoppinglist/<shoppinglist_id>', methods=['DELETE'])
@token_required
def delete_shopping_list(current_user, shoppinglist_id):
	shopping_list = ShoppingList.query.filter_by(id=shoppinglist_id, user_id=current_user.id).first()

	if not shopping_list:
		return jsonify({'message' : 'No shoppinglist found!'})

	db.session.delete(shopping_list)
	db.session.commit()

	return jsonify({'message' : 'Shopping list deleted!'})


if __name__ == '__main__':
	app.run(debug=True)