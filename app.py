from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FieldList
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///polls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Модели
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    votes = db.relationship('Vote', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(500), nullable=False)
    options = db.relationship('Option', backref='poll', lazy=True)
    votes = db.relationship('Vote', backref='poll', lazy=True)


class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    votes = db.relationship('Vote', backref='option', lazy=True)


class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('option.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Декоратор для проверки админа
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# Формы
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class PollForm(FlaskForm):
    question = StringField('Question', validators=[DataRequired(), Length(max=500)])
    options = FieldList(StringField('Option', validators=[DataRequired(), Length(max=200)]), min_entries=2, max_entries=5)
    submit = SubmitField('Create Poll')


# Роуты
@app.route('/')
def index():
    polls = Poll.query.all()
    return render_template('index.html', polls=polls)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully!')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.')
    return redirect(url_for('index'))


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_poll():
    form = PollForm()
    if form.validate_on_submit():
        poll = Poll(question=form.question.data)
        db.session.add(poll)
        db.session.commit()
        for option_text in form.options.data:
            option = Option(text=option_text, poll_id=poll.id)
            db.session.add(option)
        db.session.commit()
        flash('Poll created!')
        return redirect(url_for('index'))
    return render_template('create_poll.html', form=form)


@app.route('/poll/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def poll_detail(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    voted = Vote.query.filter_by(user_id=current_user.id, poll_id=poll_id).first()
    if request.method == 'POST' and not voted:
        option_id = request.form.get('option')
        option = Option.query.filter_by(id=option_id, poll_id=poll_id).first()
        if option:
            vote = Vote(user_id=current_user.id, poll_id=poll_id, option_id=option.id)
            db.session.add(vote)
            db.session.commit()
            flash('Vote submitted!')
            return redirect(url_for('poll_detail', poll_id=poll_id))
        else:
            flash('Invalid option.')
    votes_count = {option.id: len(option.votes) for option in poll.options}
    total_votes = sum(votes_count.values())
    return render_template('poll_detail.html', poll=poll, voted=voted, votes_count=votes_count, total_votes=total_votes)


# Админка
@app.route('/admin')
@admin_required
def admin_index():
    return render_template('admin/index.html')


@app.route('/admin/polls')
@admin_required
def admin_polls():
    polls = Poll.query.all()
    return render_template('admin/polls.html', polls=polls)


@app.route('/admin/polls/delete/<int:poll_id>', methods=['POST'])
@admin_required
def admin_delete_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    Vote.query.filter_by(poll_id=poll.id).delete()
    Option.query.filter_by(poll_id=poll.id).delete()
    db.session.delete(poll)
    db.session.commit()
    flash('Poll deleted.')
    return redirect(url_for('admin_polls'))


@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    Vote.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash('User deleted.')
    return redirect(url_for('admin_users'))

from flask import jsonify

@app.route('/api/polls', methods=['GET'])
def api_get_polls():
    polls = Poll.query.all()
    result = []
    for poll in polls:
        result.append({
            'id': poll.id,
            'question': poll.question,
            'options': [{'id': o.id, 'text': o.text} for o in poll.options]
        })
    return jsonify(result)


@app.route('/api/polls/<int:poll_id>', methods=['GET'])
def api_get_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    result = {
        'id': poll.id,
        'question': poll.question,
        'options': [{'id': o.id, 'text': o.text} for o in poll.options],
        'votes': {o.id: len(o.votes) for o in poll.options}
    }
    return jsonify(result)


@app.route('/api/polls/<int:poll_id>/vote', methods=['POST'])
def api_vote(poll_id):
    data = request.get_json()
    user_id = data.get('user_id')
    option_id = data.get('option_id')

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    poll = Poll.query.get_or_404(poll_id)
    option = Option.query.filter_by(id=option_id, poll_id=poll_id).first()
    if not option:
        return jsonify({'error': 'Invalid option'}), 400

    existing_vote = Vote.query.filter_by(user_id=user_id, poll_id=poll_id).first()
    if existing_vote:
        return jsonify({'error': 'User already voted'}), 400

    vote = Vote(user_id=user_id, poll_id=poll_id, option_id=option_id)
    db.session.add(vote)
    db.session.commit()
    return jsonify({'message': 'Vote recorded'})



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
