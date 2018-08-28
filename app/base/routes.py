from .forms import LoginForm, RegisterForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, request, jsonify, make_response,render_template,redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash



from app import db, login_manager
from app.base import blueprint
from app.base.models import User


@blueprint.route('/')
def route_default():
    form = LoginForm()
    form1 = RegisterForm()
    return redirect(url_for('base_blueprint.login', form=form, form1=form1))



@blueprint.route('/<template>')
@login_required
def route_template(template):
    return render_template(template + '.html')


@blueprint.route('/fixed_<template>')
@login_required
def route_fixed_template(template):
    return render_template('fixed/fixed_{}.html'.format(template))


@blueprint.route('/page_<error>')
def route_errors(error):
    return render_template('errors/page_{}.html'.format(error))

## Login & Registration


@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    form1 = RegisterForm()


    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        print(form.username.data)
        print(user.password)
        if user:
            if (user.password, form.password.data):
                if(user.status):
                    login_user(user, remember=form.remember.data)
                    return '<h1>admin user</h1>'
                else:
                    login_user(user, remember=form.remember.data)
                    return '<h1>normal user</h1>'



    if form1.validate_on_submit():

        hashed_password = generate_password_hash(form1.password.data, method='sha256')
        new_user = User(username=form1.username.data, email=form1.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return '<h1>user registered</h1>'

    #return redirect(url_for('home_blueprint.normal_user_index'))
    return  render_template('login/login.html', form=form, form1=form1)
    #return redirect(url_for('home_blueprint.index'))


@blueprint.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('base_blueprint.login'))


@blueprint.route('/shutdown')
def shutdown():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()
    return 'Server shutting down...'

## Errors

