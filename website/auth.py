from flask import Blueprint, render_template, request, flash, redirect, url_for, session, jsonify
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import time
import json

auth = Blueprint('auth', __name__)

blackList = {}


@auth.route('/login', methods=['GET', 'POST'])
def login():

    # catching the IP
    headers_list = request.headers.get('X-Forwarded-For', request.remote_addr)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    print(headers_list)

    pasa_flask = "pasa"

    if session.get('attempt') is None:
        print("attempt is none")
        session['attempt'] = 3

    if session.get('bloqueadoSeg') is None:
        print("bloqueadoSeg is none")
        session['bloqueadoSeg'] = 99
    else:
        print(session['bloqueadoSeg'])
        print(pasa_flask)


        if session['bloqueadoSeg'] <= 5:
            pasa_flask = "bloqueado"

        if session['bloqueadoSeg'] == 1:
            session['bloqueadoSeg'] = None
        
    if request.method == 'POST':
        print("post sended")
        # read json + reply
        data = request.get_json()

        if data:
            if isinstance(data, int):
                session['attempt'] = 0
                session['bloqueadoSeg'] = data
                print(session['bloqueadoSeg'])

            if data == "si":
                session['attempt'] = 4
                pasa_flask = "pasa"

        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                session['attempt'] = 3
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

        session['attempt'] -= 1
        
        if session['attempt']<=0:

            session['attempt'] = 0
            
            flash('%s will be blocked for 5 seconds. Attempt %d of 3'  % (client_ip,session['attempt']), 'error')

            # Created a new key in hash map with the ip and if is blocked
            #blackList[client_ip] = "yes"

            #now im sending the client ip

            return render_template("login.html", user=current_user, heart = session['attempt'], clientIp=client_ip, pasa="bloqueado")

        else:
            flash('Invalid login credentials. Attempts %d of 3'  % session['attempt'], 'error')


    return render_template("login.html", user=current_user, heart = session['attempt'], clientIp=client_ip, pasa=pasa_flask)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():

    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)
