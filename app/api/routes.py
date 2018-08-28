from flask import Flask, request, jsonify, make_response,render_template,redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from functools import wraps
import jwt
import uuid
from app.api import blueprint
from flask_login import login_required


app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/muthemba/PycharmProjects/futurenet_interview/database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)


class Commodities_data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    commodity_name = db.Column(db.String(50))
    public_id = db.Column(db.String(50), unique=True)
    commodity_amount = db.Column(db.Integer)

class transaction(db.Model):
    transaction_id = db.Column(db.String(50), unique=True, primary_key=True)
    buyers_name =  db.Column(db.String(15))
    commodity_bought = db.Column(db.String(50))
    amount_paid = db.Column(db.String(10))
    commodity_bought_amount = db.Column(db.Integer)
    status_payment = db.Column(db.Boolean)
    timestamp = db.Column(db.String(20))

class User(db.Model):
       id = db.Column(db.Integer, primary_key=True)
       username = db.Column(db.String(15), unique=True)
       email = db.Column(db.String(50), unique=True)
       password = db.Column(db.String(80))
       status = db.Column(db.Boolean)



def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Devices.query.filter_by(public_id=data['public_id']).first()

        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


######################################################### api for transactions ##########################################
@blueprint.route('/transactions', methods=['GET'])
@token_required
def all_transactions():
    transactions = transaction.query.all()
    output = []
    for trans in transactions:
        transactions_data = {}
        transactions_data['transaction_id'] = trans.transaction_id
        transactions_data['buyers_name'] = trans.buyers_name
        transactions_data['amount_paid'] = trans.amount_paid
        transactions_data['timestamp'] = trans.timestamp
        output.append(transactions_data)
    return jsonify({'transactions': output})

# get a specific transaction data
@blueprint.route('/transactions/<transaction_id>', methods=['GET'])
@token_required
def query_only_one_specific_transaction(transaction_id):
    trans = transaction.query.filter_by(public_id=transaction_id).first()

    if not trans:
          return jsonify({'message': 'No transaction with that number found!'})

    transactions_data = {}
    transactions_data['transaction_id'] = trans.transaction_id
    transactions_data['buyers_name'] = trans.buyers_name
    transactions_data['amount_paid'] = trans.amount_paid
    transactions_data['timestamp'] = trans.timestamp

    return jsonify({'transactions': transactions_data})

######################################################### crude operation ##############################################
#push data into database
@blueprint.route('/push', methods=['POST'])
@token_required
def add_data_to_db():
    data = request.get_json()
    new_tuple = Commodities_data(id=data['id'], public_id=data['public_id'], commodity_amount=data['commodity_amount'], commodity_name=data['commodity_name'])
    #check if there is a similar product with the same public id
    #if there is one just update the commodity amount column
    try:
        db.session.add(new_tuple)
        db.session.commit()
        return jsonify({'message': "new commodity added stored!"})
    except:
        commodity = Commodities_data.query.filter_by(public_id=data['public_id'])
        commodity.commodity_amount = int(commodity.commodity_amount) + int(data['commodity_amount'])
        db.session.commit()
        return jsonify({'message': "commodity amount updated !"})


#delete data into database
@blueprint.route('/delete/<public_id>', methods=['DELETE'])
@token_required
def delete_data_from_db(public_id):
    row = Commodities_data.query.filter_by(public_id=public_id).first()
    if not row:
        return jsonify({'message' : 'No commodity found!'})
    db.session.delete(row)
    db.session.commit()
    return jsonify({'message' : 'commodity has been deleted!'})


# get all commodities data
@blueprint.route('/commodities', methods=['GET'])
@token_required
def query_all_available_commodities(name_of_commodity):
    commodities = Commodities_data.query.filter_by(commodity_name=name_of_commodity).all()
    output = []
    for commodity in commodities:
        commodities_data = {}
        commodities_data['id'] = commodity.id
        commodities_data['commodity_amount'] = commodity.commodity_amount
        commodities_data['public_id'] = commodity.public_id
        output.append(commodities_data)
    return jsonify({'commodities' : output})


# get a specific commodity data
@blueprint.route('/commodities/<public_id>', methods=['GET'])
@token_required
def query_only_one_specific_commodity(public_id):
    commodity = Commodities_data.query.filter_by(public_id=public_id).first()
    if not commodity:
        return jsonify({'message' : 'No commodity with that name found!'})
    commodities_data = {}
    commodities_data['id'] = commodity.id
    commodities_data['commodity_amount'] = commodity.commodity_amount
    commodities_data['commodity_name'] = commodity.commodity_name

    return jsonify({'commodity': commodities_data})



@blueprint.route('/token')
def get_token():

    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password , auth.password):
        token = jwt.encode({'user' : user.username}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})





