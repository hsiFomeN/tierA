import datetime
import os
from flask import Flask, render_template, redirect, url_for, flash, session as flask_session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from data import db_session
from data.users import User
from data.messages import Message
from forms.auth import RegistrationForm, LoginForm
from forms.message import MessageForm
from utils.crypto import (generate_rsa_keypair, encrypt_private_key,
                          decrypt_private_key, encrypt_message_hybrid, decrypt_message_hybrid)
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db_session.global_init(Config.DATABASE)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    try:
        return db_sess.query(User).get(int(user_id))
    finally:
        db_sess.close()


@app.context_processor
def inject_globals():
    return dict(brand_logo='tierA', title='tierA')


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('inbox'))
    return render_template('base.html', title='Добро пожаловать')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('inbox'))
    form = RegistrationForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        try:
            if db_sess.query(User).filter((User.nickname == form.nickname.data) | (User.email == form.email.data)).first():
                flash('Пользователь с таким никнеймом или email уже существует.', 'danger')
                return render_template('register.html', form=form, title='Регистрация')
            private_pem, public_pem = generate_rsa_keypair()
            encrypted_private = encrypt_private_key(private_pem, form.password.data)
            hashed_pw = generate_password_hash(form.password.data)
            user = User(
                nickname=form.nickname.data,
                first_name=form.first_name.data,
                surname=form.surname.data,
                email=form.email.data,
                hashed_password=hashed_pw,
                public_key=public_pem,
                encrypted_private_key=encrypted_private
            )
            db_sess.add(user)
            db_sess.commit()
            flash('Регистрация успешна! Теперь войдите.', 'success')
            return redirect(url_for('login'))
        finally:
            db_sess.close()
    return render_template('register.html', form=form, title='Регистрация')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('inbox'))
    form = LoginForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        try:
            user = db_sess.query(User).filter(User.email == form.email.data).first()
            if user and check_password_hash(user.hashed_password, form.password.data):
                try:
                    private_pem = decrypt_private_key(user.encrypted_private_key, form.password.data)
                    login_user(user, remember=True)
                    flask_session['private_key'] = private_pem
                    flash('Вход выполнен.', 'success')
                    return redirect(url_for('inbox'))
                except Exception as e:
                    flash('Неверный пароль или повреждён ключ.', 'danger')
            else:
                flash('Неверная почта или пароль.', 'danger')
        finally:
            db_sess.close()
    return render_template('login.html', form=form, title='Вход')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flask_session.pop('private_key', None)
    return redirect(url_for('index'))


@app.route('/users')
@login_required
def users_list():
    db_sess = db_session.create_session()
    try:
        users = db_sess.query(User).all()
        return render_template('users.html', users=users, title='Пользователи')
    finally:
        db_sess.close()


@app.route('/send/<int:user_id>', methods=['GET', 'POST'])
@login_required
def send_message(user_id):
    db_sess = db_session.create_session()
    try:
        recipient = db_sess.query(User).get(user_id)
        if not recipient:
            flash('Пользователь не найден.', 'danger')
            return redirect(url_for('users_list'))
        form = MessageForm()
        if form.validate_on_submit():
            # Гибридное шифрование для получателя
            enc_key_for_recip, enc_msg_for_recip = encrypt_message_hybrid(
                form.body.data, recipient.public_key
            )
            # Копия для себя
            sender = db_sess.query(User).get(current_user.id)
            enc_key_for_self, enc_msg_for_self = encrypt_message_hybrid(
                form.body.data, sender.public_key
            )
            msg = Message(
                sender_id=current_user.id,
                recipient_id=recipient.id,
                encrypted_body=f"{enc_key_for_recip}|{enc_msg_for_recip}",
                encrypted_copy_for_sender=f"{enc_key_for_self}|{enc_msg_for_self}",
                is_read=False
            )
            db_sess.add(msg)
            db_sess.commit()
            flash('Сообщение отправлено.', 'success')
            return redirect(url_for('chat', user_id=recipient.id))
        form.recipient_id.data = recipient.id
        return render_template('send_message.html', form=form, recipient=recipient,
                               title=f'Написать {recipient.nickname}')
    finally:
        db_sess.close()


@app.route('/inbox')
@login_required
def inbox():
    private_key = flask_session.get('private_key')
    if not private_key:
        flash('Ошибка: приватный ключ не найден. Войдите заново.', 'danger')
        logout_user()
        return redirect(url_for('login'))
    db_sess = db_session.create_session()
    try:
        messages = db_sess.query(Message).filter(
            Message.recipient_id == current_user.id
        ).order_by(Message.timestamp.desc()).all()
        for msg in messages:
            if msg.encrypted_body and '|' in msg.encrypted_body:
                key64, msg64 = msg.encrypted_body.split('|', 1)
                try:
                    msg.decrypted_body = decrypt_message_hybrid(key64, msg64, private_key)
                except Exception:
                    msg.decrypted_body = "[Ошибка расшифровки]"
            else:
                msg.decrypted_body = "[Сообщение повреждено]"
        return render_template('inbox.html', messages=messages, title='Входящие')
    finally:
        db_sess.close()


@app.route('/outbox')
@login_required
def outbox():
    private_key = flask_session.get('private_key')
    if not private_key:
        flash('Ошибка: приватный ключ не найден. Войдите заново.', 'danger')
        logout_user()
        return redirect(url_for('login'))
    db_sess = db_session.create_session()
    try:
        messages = db_sess.query(Message).filter(
            Message.sender_id == current_user.id
        ).order_by(Message.timestamp.desc()).all()
        for msg in messages:
            data = msg.encrypted_copy_for_sender
            if data and '|' in data:
                key64, msg64 = data.split('|', 1)
                try:
                    msg.decrypted_body = decrypt_message_hybrid(key64, msg64, private_key)
                except Exception:
                    msg.decrypted_body = "[Ошибка расшифровки]"
            else:
                msg.decrypted_body = "[Копия отсутствует]"
        return render_template('outbox.html', messages=messages, title='Исходящие')
    finally:
        db_sess.close()


@app.route('/chat/<int:user_id>')
@login_required
def chat(user_id):
    private_key = flask_session.get('private_key')
    if not private_key:
        flash('Ошибка: приватный ключ не найден. Войдите заново.', 'danger')
        logout_user()
        return redirect(url_for('login'))
    db_sess = db_session.create_session()
    try:
        interlocutor = db_sess.query(User).get(user_id)
        if not interlocutor:
            flash('Пользователь не найден.', 'danger')
            return redirect(url_for('users_list'))

        now = datetime.datetime.utcnow()
        unread = db_sess.query(Message).filter(
            Message.sender_id == user_id,
            Message.recipient_id == current_user.id,
            Message.is_read == False
        ).all()
        for m in unread:
            m.is_read = True
            m.read_at = now
        if unread:
            db_sess.commit()

        messages = db_sess.query(Message).filter(
            ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
            ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id))
        ).order_by(Message.timestamp.asc()).all()

        for msg in messages:
            if msg.sender_id == current_user.id:
                data = msg.encrypted_copy_for_sender
            else:
                data = msg.encrypted_body
            if data and '|' in data:
                key64, msg64 = data.split('|', 1)
                try:
                    msg.decrypted_body = decrypt_message_hybrid(key64, msg64, private_key)
                except Exception:
                    msg.decrypted_body = "[Ошибка расшифровки]"
            else:
                msg.decrypted_body = "[Сообщение повреждено]"

        return render_template('chat.html', messages=messages,
                               interlocutor=interlocutor,
                               title=f'Чат с {interlocutor.nickname}')
    finally:
        db_sess.close()


@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    db_sess = db_session.create_session()
    try:
        user = db_sess.query(User).get(current_user.id)
        if user:
            db_sess.delete(user)
            db_sess.commit()
            logout_user()
            flask_session.pop('private_key', None)
            flash('Ваш аккаунт и все связанные сообщения удалены.', 'info')
            return redirect(url_for('index'))
        else:
            flash('Пользователь не найден.', 'danger')
            return redirect(url_for('users_list'))
    finally:
        db_sess.close()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 3000)))