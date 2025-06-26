from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from datetime import datetime, timedelta
import re
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_mail import Mail, Message
from dotenv import load_dotenv
from flask_mail import Message
import os
import json
import html
from newspaper import Article, Config
from newspaper.article import ArticleException
import dateutil.parser
from functools import lru_cache
from flask_caching import Cache
from flask_compress import Compress
from werkzeug.utils import secure_filename
from bs4 import BeautifulSoup
from dateutil import parser
from typing import Optional, Union, Dict, List, Any
from urllib.parse import urlparse
from flask_migrate import Migrate
from bs4 import Tag
import time
from config import Config

# Load environment variables and print debug info
print("Loading environment variables...")
load_dotenv()
print(f"MAIL_USERNAME: {os.environ.get('MAIL_USERNAME')}")
print(
    f"MAIL_APP_PASSWORD set: {'Yes' if os.environ.get('MAIL_APP_PASSWORD') else 'No'}")
print(f"Current working directory: {os.getcwd()}")
print(f".env file exists: {'Yes' if os.path.exists('.env') else 'No'}")

app = Flask(__name__)
app.config.from_object(Config)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///news.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация расширений
db = SQLAlchemy(app)
mail = Mail(app)
compress = Compress(app)
cache = Cache(app, config={
    'CACHE_TYPE': 'simple',
    'CACHE_DEFAULT_TIMEOUT': 300
})

# Очистка кэша при запуске
with app.app_context():
    cache.clear()
    print("DEBUG: Кэш очищен при запуске")

# Настройка кэширования статических файлов
# Отключаем кэширование для разработки
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['COMPRESS_ALGORITHM'] = ['gzip', 'br']
app.config['COMPRESS_MIMETYPES'] = [
    'text/html',
    'text/css',
    'text/xml',
    'application/json',
    'application/javascript',
    'application/x-javascript',
    'image/svg+xml'
]

# Инициализация расширений
compress.init_app(app)
smtp_server = "smtp.mail.ru"
smtp_port = 587

migrate = Migrate(app, db)

# Настройка заголовков кэширования для статических файлов


@app.after_request
def add_header(response):
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Оптимизированная отдача статических файлов


@app.route('/static/<path:filename>')
@cache.cached(timeout=3600)  # Кэширование на 1 час
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)


# Используем ключ из конфигурации с резервным значением
NEWS_API_KEY = app.config.get(
    'NEWS_API_KEY', '6129029f12424356a0ddc886eb4cab4e')
# Изменили на everything для получения большего количества новостей
NEWS_API_URL = 'https://newsapi.org/v2/everything'

CATEGORY_NAMES = {
    'general': 'Главные новости',
    'business': 'Бизнес',
    'technology': 'Технологии',
    'sports': 'Спорт',
    'entertainment': 'Развлечения',
    'health': 'Здоровье',
    'science': 'Наука',
    'games': 'Игры'
}

# Словарь для поисковых запросов по категориям
CATEGORY_QUERIES = {
    'general': 'россия OR мир',
    'business': 'бизнес OR экономика',
    'technology': 'технологии OR IT',
    'sports': 'спорт',
    'entertainment': 'развлечения OR культура',
    'health': 'здоровье OR медицина',
    'science': 'наука OR исследования',
    'games': 'игры OR геймдев OR gaming OR киберспорт'
}


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    nickname = db.Column(db.String(50), unique=True, index=True)
    phone = db.Column(db.String(20))
    registration_date = db.Column(
        db.DateTime, default=datetime.utcnow, index=True)
    last_login = db.Column(db.DateTime, index=True)
    login_attempts = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.DateTime)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)

    def __init__(self, email, password, nickname=None, phone=None):
        self.email = email
        self.set_password(password)
        self.nickname = nickname or email.split('@')[0]
        self.phone = phone
        self.registration_date = datetime.utcnow()

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def generate_reset_token(self):
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
        return self.reset_token

    def update_login_attempt(self, success=True):
        if success:
            self.login_attempts = 0
            self.last_login = datetime.utcnow()
        else:
            self.login_attempts += 1
            self.last_attempt = datetime.utcnow()

    @property
    def is_locked_out(self):
        if self.login_attempts >= 5 and self.last_attempt:
            lockout_duration = timedelta(minutes=15)
            return datetime.utcnow() - self.last_attempt < lockout_duration
        return False


class Comment(db.Model):
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    article_url = db.Column(db.String(500), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    parent_id = db.Column(db.Integer, db.ForeignKey('comments.id'))
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)

    # Отношения
    user = db.relationship('User', backref='comments')
    replies = db.relationship(
        'Comment', backref=db.backref('parent', remote_side=[id]))
    votes = db.relationship(
        'CommentVote', backref='comment', cascade='all, delete-orphan')


class CommentVote(db.Model):
    __tablename__ = 'comment_votes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey(
        'comments.id'), nullable=False)
    # 'like' или 'dislike'
    vote_type = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Отношения
    user = db.relationship('User', backref='comment_votes')

    # Уникальный индекс для предотвращения множественных голосов
    __table_args__ = (db.UniqueConstraint('user_id', 'comment_id'),)


class UserProfile(db.Model):
    __tablename__ = 'user_profiles'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'users.id'), unique=True, nullable=False)
    avatar_path = db.Column(
        db.String(200), default='images/default-avatar.png')
    bio = db.Column(db.Text)
    notification_preferences = db.Column(db.JSON, default={})
    preferred_categories = db.Column(db.JSON, default=[])

    # Отношения
    user = db.relationship(
        'User', backref=db.backref('profile', uselist=False))


class ViewHistory(db.Model):
    __tablename__ = 'view_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    article_url = db.Column(db.String(500), nullable=False)
    article_title = db.Column(db.String(200), nullable=False)
    viewed_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Отношения
    user = db.relationship('User', backref='view_history')


class Favorite(db.Model):
    __tablename__ = 'favorites'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    article_url = db.Column(db.String(500), nullable=False)
    article_title = db.Column(db.String(200), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Отношения
    user = db.relationship('User', backref='favorites')

    # Уникальный индекс для предотвращения дублирования
    __table_args__ = (db.UniqueConstraint('user_id', 'article_url'),)


class ArticleCache(db.Model):
    __tablename__ = 'article_cache'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False, unique=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    published_at = db.Column(db.DateTime)
    image_url = db.Column(db.String(500))
    source_name = db.Column(db.String(200))
    cached_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


with app.app_context():
    db.create_all()


@cache.memoize(timeout=3600)  # Кэширование на 1 час
def get_full_article_content(url: str) -> tuple[Optional[str], Optional[str]]:
    try:
        # Конфигурация для newspaper3k
        config = Config()
        config.browser_user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        config.request_timeout = 10
        config.fetch_images = False

        article = Article(url, language='ru', config=config)
        article.download()
        article.parse()

        # Получаем текст и дату публикации
        text = article.text
        publish_date = article.publish_date

        # Если не удалось получить текст через newspaper, пробуем получить через requests
        if not text:
            try:
                response = requests.get(url,
                                        headers={
                                            'User-Agent': config.browser_user_agent},
                                        timeout=config.request_timeout
                                        )
                response.raise_for_status()

                # Используем BeautifulSoup для извлечения текста
                soup = BeautifulSoup(response.text, 'html.parser')

                # Удаляем ненужные элементы
                for tag in soup(['script', 'style', 'nav', 'header', 'footer', 'iframe']):
                    tag.decompose()

                # Получаем основной контент
                content_tags = soup.find_all(['p', 'article', 'div'],
                                             class_=lambda x: x and isinstance(x, str) and
                                             any(word in x.lower() for word in [
                                                 'content', 'article', 'text', 'body'])
                                             )

                if content_tags:
                    text = '\n'.join(tag.get_text() for tag in content_tags)

                if not publish_date:
                    # Пытаемся найти дату в метатегах
                    meta_date = soup.find(
                        'meta', property=['article:published_time', 'og:published_time'])
                    if meta_date and meta_date.get('content'):
                        try:
                            publish_date = parser.parse(
                                meta_date.get('content'))
                        except (ValueError, TypeError):
                            publish_date = None
            except Exception as e:
                print(f"Error extracting content with requests: {e}")

        if not text:
            return None, None

        text = clean_article_content(text)

        if publish_date:
            publish_date = publish_date.strftime('%d.%m.%Y %H:%M')

        return text, publish_date
    except Exception as e:
        print(f"Error extracting article: {e}")
        return None, None


def clean_article_content(content):
    if not content:
        return None

    try:
        # Декодируем HTML-сущности
        cleaned = html.unescape(content)

        # Удаляем HTML-теги
        cleaned = re.sub(r'<[^>]+>', '', cleaned)

        # Удаляем множественные пробелы, переносы строк и табуляции
        cleaned = re.sub(r'[\s\t\n\r]+', ' ', cleaned)

        # Удаляем пробелы перед знаками пунктуации
        cleaned = re.sub(r'\s+([.,!?;:])', r'\1', cleaned)

        # Удаляем повторяющиеся знаки пунктуации
        cleaned = re.sub(r'([.,!?;:]){2,}', r'\1', cleaned)

        cleaned = cleaned.strip()

        # Проверяем минимальную длину текста
        if len(cleaned) < 10:
            return None

        return cleaned

    except Exception as e:
        print(f"Error cleaning content: {e}")
        return None


@cache.memoize(timeout=300)  # Кэширование на 5 минут
def get_news(category='general', search_query=None):
    try:
        # Проверяем, существует ли категория
        if category not in CATEGORY_QUERIES:
            print(
                f"DEBUG: Категория {category} не найдена, используем general")
            category = 'general'

        # Добавляем отладочный вывод
        print("DEBUG: Запрос новостей для категории:", category)
        print("DEBUG: Поисковый запрос:", search_query)

        base_query = CATEGORY_QUERIES[category]
        print("DEBUG: Базовый запрос для категории:", base_query)

        if search_query:
            base_query = f"{search_query} AND ({base_query})"
        print("DEBUG: Итоговый запрос:", base_query)

        params = {
            'apiKey': NEWS_API_KEY,
            'q': base_query,
            'language': 'ru',
            'pageSize': 100,
            'sortBy': 'publishedAt'
        }

        response = requests.get(
            NEWS_API_URL, params=params, timeout=10)  # Добавляем timeout
        response.raise_for_status()

        news_data = response.json()
        if news_data.get('status') != 'ok':
            print("DEBUG: Ошибка API:", news_data)
            return []

        articles = news_data.get('articles', [])
        print("DEBUG: Получено статей:", len(articles))

        # Используем list comprehension вместо цикла for для оптимизации
        filtered_articles = []
        for article in articles:
            if not article.get('title'):
                continue

            # Безопасное получение данных источника
            source = article.get('source')
            source_name = None
            if isinstance(source, dict):
                source_name = source.get('name')
            elif isinstance(source, str):
                source_name = source

            # Формируем данные статьи
            article_data = {
                'title': article.get('title'),
                'content': clean_article_content(article.get('content')),
                'description': clean_article_content(article.get('description')),
                'url': article.get('url'),
                'urlToImage': article.get('urlToImage'),
                'publishedAt': format_date(article.get('publishedAt')),
                'source': source_name
            }

            # Проверяем наличие контента
            if article_data['content'] or article_data['description']:
                filtered_articles.append(article_data)

        print("DEBUG: Отфильтровано статей:", len(filtered_articles))
        return filtered_articles

    except requests.exceptions.RequestException as e:
        print(f"Request Error: {e}")
        return []
    except Exception as e:
        print(f"Error: {e}")
        return []


def format_date(date_str):
    """Отдельная функция для форматирования даты"""
    if not date_str:
        return None
    try:
        date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%SZ')
        return date.strftime('%d.%m.%Y %H:%M')
    except Exception:
        return None


def validate_password(password):
    if len(password) < 8:
        return False, "Пароль должен содержать минимум 8 символов"
    if not re.search(r"[a-z]", password):
        return False, "Пароль должен содержать строчные буквы"
    if not re.search(r"[A-Z]", password):
        return False, "Пароль должен содержать заглавные буквы"
    if not re.search(r"\d", password):
        return False, "Пароль должен содержать цифры"
    if not re.search(r"[@$!%*?&\-_]", password):
        return False, "Пароль должен содержать специальные символы (@$!%*?&-_)"
    return True, "Пароль соответствует требованиям"


def send_reset_email(user_email, reset_token):
    try:
        subject = 'Восстановление пароля'
        reset_link = f"http://{request.host}/reset_password/{reset_token}"
        body = f"""
        Вы запросили восстановление пароля.
        
        Для сброса пароля перейдите по ссылке:
        {reset_link}
        
        Ссылка действительна в течение 1 часа.
        
        Если вы не запрашивали сброс пароля, проигнорируйте это письмо.
        """

        sender = app.config.get(
            'MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME')
        if not sender:
            print("Error: No sender email configured")
            return False

        msg = Message(
            subject,
            sender=sender,
            recipients=[user_email],
            body=body
        )
        print(f"Attempting to send email to {user_email} from {sender}")
        print(
            f"SMTP settings: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
        print(
            f"Using SSL: {app.config.get('MAIL_USE_SSL', False)}, Using TLS: {app.config.get('MAIL_USE_TLS', False)}")
        mail.send(msg)
        print("Email sent successfully")
        return True
    except Exception as e:
        print(f"Detailed error sending email: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False


@app.route('/request_reset', methods=['GET', 'POST'])
def request_reset():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Пожалуйста, введите email')
            return redirect(url_for('index'))

        user = User.query.filter_by(email=email).first()

        if user:
            # Генерируем токен и устанавливаем срок действия
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)

            try:
                db.session.commit()
                if send_reset_email(email, token):
                    flash(
                        'Инструкции по восстановлению пароля отправлены на вашу почту')
                else:
                    db.session.rollback()
                    flash(
                        'Произошла ошибка при отправке email. Пожалуйста, попробуйте позже.')
            except Exception as e:
                db.session.rollback()
                print(f"Database error: {str(e)}")
                flash('Произошла ошибка. Пожалуйста, попробуйте позже.')
        else:
            # Для безопасности не сообщаем, что пользователь не найден
            flash(
                'Если указанный email зарегистрирован, инструкции по восстановлению будут отправлены')

        return redirect(url_for('index'))

    return redirect(url_for('index'))


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user or not user.reset_token_expiry or user.reset_token_expiry < datetime.utcnow():
        flash('Недействительная или истекшая ссылка для сброса пароля')
        return redirect(url_for('index'))

    if request.method == 'POST':
        password = request.form.get('password')

        # Проверяем новый пароль
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message)
            return render_template('reset_password.html')

        # Обновляем пароль и сбрасываем токен
        user.password = generate_password_hash(password)
        user.reset_token = None
        user.reset_token_expiry = None
        user.login_attempts = 0
        user.last_attempt = None
        db.session.commit()

        flash('Ваш пароль успешно изменен')
        return redirect(url_for('index'))

    return render_template('reset_password.html')


@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' in session:
        return redirect(url_for('news'))

    if request.method == 'GET':
        return render_template('index.html', show_reset=True)

    if request.method == 'POST':
        # Теперь принимаем login вместо email
        login = request.form.get('login')
        password = request.form.get('password')
        action = request.form.get('action')

        if not login or not password:
            flash('Пожалуйста, заполните обязательные поля!')
            return render_template('index.html', show_reset=True)

        if action == 'register':
            # Проверяем валидность пароля
            is_valid, message = validate_password(password)
            if not is_valid:
                flash(message)
                return render_template('index.html', show_reset=True)

            # Проверяем уникальность email и nickname
            if User.query.filter_by(email=login).first():
                flash('Email уже зарегистрирован!')
                return render_template('index.html', show_reset=True)

            nickname = request.form.get('nickname')
            if nickname and User.query.filter_by(nickname=nickname).first():
                flash('Этот псевдоним уже занят!')
                return render_template('index.html', show_reset=True)

            phone = request.form.get('phone')
            hashed_password = generate_password_hash(password)
            new_user = User(
                email=login,
                password=hashed_password,
                nickname=nickname,
                phone=phone
            )
            new_user.last_login = datetime.utcnow()
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            return redirect(url_for('news'))

        elif action == 'login':
            # Ищем пользователя по email или nickname
            user = User.query.filter(
                (User.email == login) | (User.nickname == login)
            ).first()

            if user:
                # Проверяем, не заблокирован ли пользователь
                if user.login_attempts and user.login_attempts >= 3:
                    if user.last_attempt and datetime.utcnow() - user.last_attempt < timedelta(minutes=15):
                        flash(
                            'Слишком много попыток входа. Попробуйте позже или восстановите пароль')
                        return render_template('index.html', show_reset=True)
                    else:
                        # Сбрасываем счетчик после 15 минут
                        user.login_attempts = 0

                if check_password_hash(user.password, password):
                    user.last_login = datetime.utcnow()
                    user.login_attempts = 0
                    user.last_attempt = None
                    db.session.commit()
                    session['user_id'] = user.id
                    return redirect(url_for('news'))
                else:
                    user.login_attempts = (user.login_attempts or 0) + 1
                    user.last_attempt = datetime.utcnow()
                    db.session.commit()

                    if user.login_attempts >= 3:
                        flash(
                            'Слишком много попыток входа. Попробуйте позже или восстановите пароль')
                        return render_template('index.html', show_reset=True)
                    else:
                        flash('Неверный пароль!')
            else:
                flash('Пользователь не найден!')

    return render_template('index.html')


@app.route('/news')
def news():
    category = request.args.get('category', 'general')
    search = request.args.get('search', '')

    # Данные пользователя только для авторизованных
    user = None
    hours_online = 0
    minutes_online = 0

    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            # Расчет времени онлайн только для авторизованных
            registration_time = user.registration_date
            current_time = datetime.utcnow()
            time_diff = current_time - registration_time
            hours_online = time_diff.days * 24 + time_diff.seconds // 3600
            minutes_online = (time_diff.seconds % 3600) // 60

    try:
        articles = get_news(category, search)

        # Добавляем отладочный вывод
        print("DEBUG: Категории:", CATEGORY_NAMES)
        print("DEBUG: Текущая категория:", category)

        return render_template('news.html',
                               articles=articles,
                               categories=CATEGORY_NAMES,
                               current_category=category,
                               user=user,
                               hours_online=hours_online,
                               minutes_online=minutes_online,
                               datetime=datetime)

    except Exception as e:
        print(f"Error fetching news: {str(e)}")
        flash(
            'Произошла ошибка при загрузке новостей. Пожалуйста, попробуйте позже.', 'error')
        return render_template('news.html',
                               articles=[],
                               categories=CATEGORY_NAMES,
                               current_category=category,
                               user=user,
                               hours_online=hours_online,
                               minutes_online=minutes_online,
                               datetime=datetime)


@app.route('/article/<path:article_url>')
def article(article_url):
    user = None
    hours_online = 0
    minutes_online = 0

    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            # Расчет времени онлайн только для авторизованных пользователей
            registration_time = user.registration_date
            current_time = datetime.utcnow()
            time_diff = current_time - registration_time
            hours_online = time_diff.days * 24 + time_diff.seconds // 3600
            minutes_online = (time_diff.seconds % 3600) // 60

    category = request.args.get('category', 'general')
    search = request.args.get('search', '')

    print("DEBUG: Загрузка статьи:", article_url)

    try:
        article_content = None
        article_date = None
        source_name = None
        article_image = None
        article_title = None

        # Пытаемся загрузить статью из кэша
        cached_article = ArticleCache.query.filter_by(url=article_url).first()
        cache_valid = cached_article and cached_article.cached_at and \
            (datetime.utcnow() -
             cached_article.cached_at).total_seconds() < 3600  # Кэш на 1 час

        if cache_valid and cached_article:  # Проверяем, что cached_article не None
            article_content = cached_article.content
            article_date = cached_article.published_at
            source_name = cached_article.source_name
            article_image = cached_article.image_url
            article_title = cached_article.title
        else:
            # Если нет в кэше или устарел, загружаем заново
            try:
                article = Article(article_url, language='ru')
                article.download()
                article.parse()

                article_content = article.text
                article_date = article.publish_date
                source_name = urlparse(article_url).netloc
                article_image = article.top_image
                article_title = article.title

                # Сохраняем в кэш
                if cached_article:
                    cached_article.title = article.title
                    cached_article.content = article.text
                    cached_article.published_at = article.publish_date
                    cached_article.image_url = article.top_image
                    cached_article.source_name = urlparse(article_url).netloc
                    cached_article.cached_at = datetime.utcnow()
                else:
                    new_cache = ArticleCache(
                        url=article_url,
                        title=article.title,
                        content=article.text,
                        published_at=article.publish_date,
                        image_url=article.top_image,
                        source_name=urlparse(article_url).netloc,
                        cached_at=datetime.utcnow()
                    )
                    db.session.add(new_cache)
                db.session.commit()

            except ArticleException as e:
                print(f"Error extracting article: {str(e)}")
                # Если не удалось загрузить, используем данные из кэша, даже если они устарели
                if cached_article:
                    article_content = cached_article.content
                    article_date = cached_article.published_at
                    source_name = cached_article.source_name
                    article_image = cached_article.image_url
                    article_title = cached_article.title
                else:
                    # Если нет в кэше, показываем сообщение об ошибке
                    flash(
                        'Не удалось загрузить статью. Пожалуйста, попробуйте позже.', 'error')
                    return redirect(url_for('news', category=category, search=search))

        # Форматируем дату
        formatted_date = None
        if article_date:
            if isinstance(article_date, str):
                try:
                    article_date = datetime.strptime(
                        article_date, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    pass
            if isinstance(article_date, datetime):
                formatted_date = article_date.strftime('%d.%m.%Y %H:%M')

        # Проверяем URL изображения
        if article_image and not article_image.startswith(('http://', 'https://')):
            article_image = None

        # Формируем данные для шаблона
        template_data = {
            'article_title': article_title or 'Статья',
            'article_content': article_content or 'Текст статьи недоступен',
            'article_date': formatted_date,
            'article_image': article_image,
            'article_source': source_name,
            'article_url': article_url,
            'category': category,
            'search': search,
            'user': user,
            'hours_online': hours_online,
            'minutes_online': minutes_online,
            'datetime': datetime,
            'is_favorite': user and Favorite.query.filter_by(
                user_id=user.id,
                article_url=article_url
            ).first() is not None,
            'comments': Comment.query.filter_by(
                article_url=article_url,
                parent_id=None
            ).order_by(Comment.created_at.desc()).all()
        }

        print("DEBUG: Данные для шаблона:", template_data)

        # Добавляем запись в историю просмотров только для авторизованных пользователей
        if user:
            view_history = ViewHistory(
                user_id=user.id,
                article_url=article_url,
                article_title=template_data['article_title']
            )
            db.session.add(view_history)
            db.session.commit()

        return render_template('article.html', **template_data)

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        flash(
            'Произошла ошибка при загрузке статьи. Пожалуйста, попробуйте позже.', 'error')
        return redirect(url_for('news', category=category, search=search))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = db.session.get(User, session['user_id'])
    if not user:
        return redirect(url_for('index'))

    # Получаем профиль пользователя
    profile = UserProfile.query.filter_by(user_id=user.id).first()
    if not profile:
        # Если профиль не существует, создаем новый
        profile = UserProfile(user_id=user.id)
        db.session.add(profile)
        db.session.commit()

    # Получаем историю просмотров и избранное
    view_history = ViewHistory.query.filter_by(user_id=user.id).order_by(
        ViewHistory.viewed_at.desc()).limit(10).all()
    favorites = Favorite.query.filter_by(
        user_id=user.id).order_by(Favorite.added_at.desc()).all()

    if request.method == 'POST':
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                # Создаем директорию для аватаров, если она не существует
                avatar_dir = os.path.join(app.root_path, 'static', 'uploads', 'avatars')
                if not os.path.exists(avatar_dir):
                    os.makedirs(avatar_dir)

                # Генерируем уникальное имя файла
                filename = secure_filename(f"{user.id}_{int(time.time())}_{file.filename}")
                file_path = os.path.join(avatar_dir, filename)
                
                # Добавляем логирование
                print(f"Сохраняем аватар: {file_path}")
                
                # Сохраняем файл
                file.save(file_path)
                
                relative_path = os.path.join('uploads', 'avatars', filename)
                profile.avatar_path = relative_path
                print(f"Обновляем путь к аватару: {relative_path}")
                
                db.session.commit()

                flash('Аватар успешно обновлен', 'success')
                return redirect(url_for('profile'))

    return render_template('profile.html',
                         user=user,
                         profile=profile,
                         view_history=view_history,
                         favorites=favorites,
                         theme=session.get('theme', 'light'))


@app.route('/comment/add', methods=['POST'])
def add_comment():
    if 'user_id' not in session:
        return jsonify({'error': 'Необходима авторизация'}), 401

    content = request.form.get('content')
    article_url = request.form.get('article_url')
    parent_id = request.form.get('parent_id')

    if not content or not article_url:
        return jsonify({'error': 'Необходимо заполнить все поля'}), 400

    try:
        parent_id = int(
            parent_id) if parent_id and parent_id != 'null' else None
    except ValueError:
        parent_id = None

    comment = Comment(
        content=content,
        article_url=article_url,
        user_id=session['user_id'],
        parent_id=parent_id
    )

    try:
        db.session.add(comment)
        db.session.commit()

        return jsonify({
            'id': comment.id,
            'content': comment.content,
            'created_at': comment.created_at.strftime('%d.%m.%Y %H:%M'),
            'user': comment.user.nickname or comment.user.email,
            'likes': 0,
            'dislikes': 0,
            'parent_id': comment.parent_id
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error adding comment: {str(e)}")
        return jsonify({'error': 'Ошибка при сохранении комментария'}), 500


@app.route('/comment/<int:comment_id>/vote', methods=['POST'])
def vote_comment(comment_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Необходима авторизация'}), 401

    user = db.session.get(User, session['user_id'])
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    comment = db.session.get(Comment, comment_id)
    if not comment:
        return jsonify({'error': 'Комментарий не найден'}), 404

    # Изменено с 'type' на 'vote_type'
    vote_type = request.form.get('vote_type')
    if vote_type not in ['like', 'dislike']:
        return jsonify({'error': 'Неверный тип голоса'}), 400

    try:
        # Проверяем, голосовал ли пользователь за этот комментарий
        existing_vote = CommentVote.query.filter_by(
            user_id=user.id,
            comment_id=comment_id
        ).first()

        if existing_vote:
            if existing_vote.vote_type == vote_type:
                # Отменяем голос
                if vote_type == 'like':
                    comment.likes -= 1
                else:
                    comment.dislikes -= 1
                db.session.delete(existing_vote)
            else:
                # Меняем голос
                if vote_type == 'like':
                    comment.dislikes -= 1
                    comment.likes += 1
                else:
                    comment.likes -= 1
                    comment.dislikes += 1
                existing_vote.vote_type = vote_type
        else:
            # Создаем новый голос
            new_vote = CommentVote(
                user_id=user.id,
                comment_id=comment_id,
                vote_type=vote_type
            )
            db.session.add(new_vote)
            if vote_type == 'like':
                comment.likes += 1
            else:
                comment.dislikes += 1

        db.session.commit()

        return jsonify({
            'likes': comment.likes,
            'dislikes': comment.dislikes,
            'vote_type': vote_type
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error processing vote: {str(e)}")
        return jsonify({'error': 'Ошибка при обработке голоса'}), 500


@app.route('/favorite/toggle', methods=['POST'])
def toggle_favorite():
    if 'user_id' not in session:
        return jsonify({'error': 'Необходима авторизация'}), 401

    article_url = request.form.get('article_url')
    article_title = request.form.get('article_title')

    if not article_url or not article_title:
        return jsonify({'error': 'Необходимо указать URL и заголовок статьи'}), 400

    existing_favorite = Favorite.query.filter_by(
        user_id=session['user_id'],
        article_url=article_url
    ).first()

    if existing_favorite:
        db.session.delete(existing_favorite)
        is_favorite = False
    else:
        new_favorite = Favorite(
            user_id=session['user_id'],
            article_url=article_url,
            article_title=article_title
        )
        db.session.add(new_favorite)
        is_favorite = True

    db.session.commit()

    return jsonify({'is_favorite': is_favorite})


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    # Определяем базовую директорию для загрузок
    base_dir = os.path.join(app.root_path, 'static', 'uploads')
    
    # Проверяем, содержит ли путь поддиректорию
    if '/' in filename:
        subdir = os.path.dirname(filename)
        full_dir = os.path.join(base_dir, subdir)
        if not os.path.exists(full_dir):
            os.makedirs(full_dir)
    
    # Возвращаем файл из static/uploads
    return send_from_directory(os.path.join(app.root_path, 'static'), filename)


def parse_article_date(article_html):
    try:
        # Ищем дату в метатегах
        meta_date = article_html.find(
            'meta', {'property': 'article:published_time'})
        if meta_date and isinstance(meta_date, Tag):
            date_str = meta_date.get('content')
            if date_str:
                return parse(date_str)

        # Ищем дату в других форматах
        date_class = article_html.find(
            'time', {'class': lambda x: x and 'date' in x.lower()})
        if date_class and isinstance(date_class, Tag):
            date_str = date_class.get('datetime') or date_class.text
            if date_str:
                return parse(date_str)

        return None
    except Exception as e:
        print(f"Error parsing date: {str(e)}")
        return None


@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    if not all([username, email, password]):
        flash('Пожалуйста, заполните все поля', 'error')
    return redirect(url_for('index'))

    if User.query.filter_by(username=username).first():
        flash('Пользователь с таким именем уже существует', 'error')
        return redirect(url_for('index'))

    if User.query.filter_by(email=email).first():
        flash('Пользователь с таким email уже существует', 'error')
        return redirect(url_for('index'))

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    flash('Регистрация успешна! Теперь вы можете войти.', 'success')
    return redirect(url_for('index'))


def get_cached_article(article_url):
    cached_article = db.session.query(
        ArticleCache).filter_by(url=article_url).first()
    if cached_article:
        return {
            'title': cached_article.title or 'Без названия',
            'content': cached_article.content or 'Содержимое недоступно',
            'published_at': cached_article.published_at,
            'image_url': cached_article.image_url,
            'source_name': cached_article.source_name
        }
    return None


@app.route('/favorites')
def favorites():
    if 'user_id' not in session:
        flash('Для доступа к избранному необходимо войти в систему')
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])
    favorites = Favorite.query.filter_by(
        user_id=user.id).order_by(Favorite.added_at.desc()).all()

    return render_template('favorites.html',
                           favorites=favorites,
                           user=user,
                           categories=CATEGORY_NAMES)


@app.route('/history')
def history():
    if 'user_id' not in session:
        flash('Для доступа к истории необходимо войти в систему')
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])
    history = ViewHistory.query.filter_by(user_id=user.id).order_by(
        ViewHistory.viewed_at.desc()).all()

    return render_template('history.html',
                           history=history,
                           user=user,
                           categories=CATEGORY_NAMES)


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        flash('Для доступа к настройкам необходимо войти в систему')
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])
    profile = UserProfile.query.filter_by(user_id=user.id).first()

    if request.method == 'POST':
        # Обработка загрузки аватара
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and file.filename:
                # Проверка расширения файла
                if '.' in file.filename and \
                   file.filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_IMAGE_EXTENSIONS']:
                    # Генерация безопасного имени файла
                    filename = secure_filename(f"{user.id}_{int(time.time())}_{file.filename}")
                    # Сохранение файла
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'avatars', filename))
                    # Обновление пути к аватару в профиле пользователя
                    profile = UserProfile.query.filter_by(user_id=user.id).first()
                    if profile:
                        profile.avatar_path = filename
                        db.session.commit()
                else:
                    flash('Разрешены только изображения форматов: png, jpg, jpeg, gif', 'error')

        # Обработка других настроек
        nickname = request.form.get('nickname')
        bio = request.form.get('bio')
        preferred_categories = request.form.getlist('preferred_categories')
        email_notifications = 'email_notifications' in request.form
        browser_notifications = 'browser_notifications' in request.form
        new_password = request.form.get('new_password')

        # Обновление профиля
        profile = UserProfile.query.filter_by(user_id=user.id).first()
        if not profile:
            profile = UserProfile(user_id=user.id)
            db.session.add(profile)

        if nickname:
            user.nickname = nickname
        profile.bio = bio
        profile.preferred_categories = preferred_categories
        profile.notification_preferences = {
            'email_notifications': email_notifications,
            'browser_notifications': browser_notifications
        }

        # Обновление пароля
        if new_password:
            if validate_password(new_password):
                user.set_password(new_password)
            else:
                flash('Новый пароль не соответствует требованиям безопасности')
                return redirect(url_for('settings'))

        db.session.commit()
        flash('Настройки успешно сохранены', 'success')
        return redirect(url_for('settings'))

    # Получение текущих настроек для отображения
    profile = UserProfile.query.filter_by(user_id=user.id).first()
    categories = {
        'main': 'Главные новости',
        'business': 'Бизнес',
        'technology': 'Технологии',
        'entertainment': 'Развлечения',
        'sports': 'Спорт',
        'health': 'Здоровье',
        'science': 'Наука',
        'games': 'Игры'
    }
    
    return render_template('settings.html', 
                         user=user, 
                         profile=profile, 
                         categories=categories)


@app.route('/update_preferences', methods=['POST'])
def update_preferences():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = db.session.get(User, session['user_id'])
    if not user:
        return redirect(url_for('index'))

    # Получаем выбранные категории из формы
    selected_categories = request.form.getlist('categories')
    
    # Обновляем профиль пользователя
    user_profile = UserProfile.query.filter_by(user_id=user.id).first()
    if not user_profile:
        user_profile = UserProfile(user_id=user.id)
        db.session.add(user_profile)
    
    user_profile.preferred_categories = selected_categories
    db.session.commit()

    flash('Предпочтения успешно обновлены', 'success')
    return redirect(url_for('profile'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
