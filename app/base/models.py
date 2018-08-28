from app import db, login_manager
from flask_login import UserMixin


class User(db.Model, UserMixin):

    __tablename__ = 'User'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    status = db.Column(db.Boolean)


    def __init__(self, **kwargs):
        for property, value in kwargs.items():
            if hasattr(value, '__iter__') and not isinstance(value, str):
                # the ,= unpack of a singleton fails PEP8 (travis flake8 test)
                value = value[0]
            setattr(self, property, value)

    def __repr__(self):
        return str(self.username)


class Commodities_data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    commodity_name = db.Column(db.String(50))
    public_id = db.Column(db.String(50), unique=True)
    commodity_amount = db.Column(db.Integer)


class transaction(db.Model):
    transaction_id = db.Column(db.String(50), unique=True, primary_key=True)
    buyers_name = db.Column(db.String(15))
    commodity_bought = db.Column(db.String(50))
    amount_paid = db.Column(db.String(10))
    commodity_bought_amount = db.Column(db.Integer)
    status_payment = db.Column(db.Boolean)
    timestamp = db.Column(db.String(20))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = User.query.filter_by(username=username).first()
    return user if user else None
