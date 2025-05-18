import os
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, SubmitField, FieldList
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import matplotlib.pyplot as plt

UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///polls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    avatar_filename = db.Column(db.String(300), nullable=True)
    votes = db.relationship('Vote', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(500), nullable=False)
    image_filename = db.Column(db.String(300))
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


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


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


class PasswordChangeForm(FlaskForm):
    old_password = PasswordField('Current password', validators=[DataRequired()])
    new_password = PasswordField('New password', validators=[DataRequired(), Length(min=6)])
    new_password2 = PasswordField('Repeat new password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change password')


class AvatarUploadForm(FlaskForm):
    avatar = FileField('Upload Avatar', validators=[FileAllowed(ALLOWED_EXTENSIONS, 'Images only!')])
    submit = SubmitField('Upload')


class PollForm(FlaskForm):
    question = StringField('Question', validators=[DataRequired(), Length(max=500)])
    image = FileField('Image', validators=[FileAllowed(ALLOWED_EXTENSIONS, 'Images only!')])
    options = FieldList(StringField('Option', validators=[DataRequired(), Length(max=200)]), min_entries=2)
    submit = SubmitField('Create Poll')


def create_poll_chart(poll):
    labels = [option.text for option in poll.options]
    votes = [len(option.votes) for option in poll.options]

    plt.figure(figsize=(6, 4))
    bars = plt.bar(labels, votes, color='skyblue')
    plt.title('Poll Results')
    plt.xlabel('Options')
    plt.ylabel('Votes')
    plt.ylim(0, max(votes + [1]) + 1)

    for bar, vote in zip(bars, votes):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1, str(vote), ha='center')

    graph_folder = os.path.join(app.static_folder, 'graphs')
    os.makedirs(graph_folder, exist_ok=True)
    filename = f'poll_{poll.id}.png'
    filepath = os.path.join(graph_folder, filename)
    plt.tight_layout()
    plt.savefig(filepath)
    plt.close()
    return filename


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
        flash('Registered successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    pwd_form = PasswordChangeForm()
    avatar_form = AvatarUploadForm()

    if pwd_form.validate_on_submit() and 'change_password' in request.form:
        if not current_user.check_password(pwd_form.old_password.data):
            flash('Current password is incorrect.', 'danger')
        else:
            current_user.set_password(pwd_form.new_password.data)
            db.session.commit()
            flash('Password updated successfully.', 'success')
            return redirect(url_for('profile'))

    if avatar_form.validate_on_submit() and 'upload_avatar' in request.form:
        if avatar_form.avatar.data:
            file = avatar_form.avatar.data
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.avatar_filename = filename
                db.session.commit()
                flash('Avatar uploaded successfully!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Invalid file format.', 'danger')

    votes = Vote.query.filter_by(user_id=current_user.id).all()
    polls_voted = {}
    for vote in votes:
        poll = Poll.query.get(vote.poll_id)
        if poll:
            polls_voted[poll] = vote.option.text

    return render_template('profile.html', pwd_form=pwd_form, avatar_form=avatar_form, polls_voted=polls_voted)


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_poll():
    form = PollForm()

    if request.method == 'POST':
        if 'add_option' in request.form:
            form.options.append_entry()
            return render_template('create_poll.html', form=form)

        if form.validate_on_submit():
            filename = None
            if form.image.data:
                file = form.image.data
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                else:
                    flash('Invalid image format.', 'danger')
                    return redirect(request.url)

            poll = Poll(question=form.question.data, image_filename=filename)
            db.session.add(poll)
            db.session.commit()
            for option_text in form.options.data:
                option = Option(text=option_text, poll_id=poll.id)
                db.session.add(option)
            db.session.commit()
            flash('Poll created!')
            return redirect(url_for('index'))

    if len(form.options) == 0:
        for _ in range(2):
            form.options.append_entry()

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
            flash('Invalid option.', 'danger')
    votes_count = {option.id: len(option.votes) for option in poll.options}
    total_votes = sum(votes_count.values())

    chart_filename = None
    if voted:
        chart_filename = create_poll_chart(poll)

    return render_template('poll_detail.html', poll=poll, voted=voted, votes_count=votes_count, total_votes=total_votes, chart_filename=chart_filename)


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
    flash('Poll deleted.', 'success')
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
    flash('User deleted.', 'success')
    return redirect(url_for('admin_users'))


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(debug=True)