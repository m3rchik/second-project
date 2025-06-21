from flask import Flask, render_template, request, redirect, url_for, flash, session
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
from newspaper import Article
from newspaper.article import ArticleException
import dateutil.parser

# Load environment variables and print debug info
print("Loading environment variables...")
load_dotenv()
print(f"MAIL_USERNAME: {os.environ.get('MAIL_USERNAME')}")
print(f"MAIL_APP_PASSWORD set: {'Yes' if os.environ.get('MAIL_APP_PASSWORD') else 'No'}")
print(f"Current working directory: {os.getcwd()}")
print(f".env file exists: {'Yes' if os.path.exists('.env') else 'No'}")

app = Flask(__name__)
app.config.from_object('config')
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# SMTP configuration is now handled in config.py

smtp_server = "smtp.mail.ru"
smtp_port = 587

db = SQLAlchemy(app)

# Initialize Flask-Mail
mail = Mail(app)

# Добавляем заголовки для совместимости с Safari
@app.after_request
def add_header(response):
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response

NEWS_API_KEY = app.config.get('NEWS_API_KEY', '6129029f12424356a0ddc886eb4cab4e')  # Используем ключ из конфигурации с резервным значением
NEWS_API_URL = 'https://newsapi.org/v2/everything'  # Изменили на everything для получения большего количества новостей

CATEGORY_NAMES = {
    'general': 'Главные новости',
    'business': 'Бизнес',
    'technology': 'Технологии',
    'sports': 'Спорт',
    'entertainment': 'Развлечения',
    'health': 'Здоровье',
    'science': 'Наука'
}

# Словарь для поисковых запросов по категориям
CATEGORY_QUERIES = {
    'general': 'россия OR мир',
    'business': 'бизнес OR экономика',
    'technology': 'технологии OR IT',
    'sports': 'спорт',
    'entertainment': 'развлечения OR культура',
    'health': 'здоровье OR медицина',
    'science': 'наука OR исследования'
}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    nickname = db.Column(db.String(50), unique=True)
    phone = db.Column(db.String(20))
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    login_attempts = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.DateTime)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)

with app.app_context():
    db.create_all()

def get_full_article_content(url):
    try:
        # Создаем объект статьи
        article = Article(url, language='ru')
        
        # Загружаем и парсим статью
        article.download()
        article.parse()
        
        # Получаем текст и дату публикации
        text = article.text
        publish_date = article.publish_date
        
        if not text:
            return None, None
            
        # Очищаем текст
        text = clean_article_content(text)
        
        # Форматируем дату
        if publish_date:
            publish_date = publish_date.strftime('%d.%m.%Y %H:%M')
            
        return text, publish_date
    except ArticleException as e:
        print(f"Error extracting article content: {e}")
        return None, None
    except Exception as e:
        print(f"Unexpected error while extracting article: {e}")
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

def get_news(category='general', search_query=None):
    try:
        base_query = CATEGORY_QUERIES[category]
        if search_query:
            base_query = f"{search_query} AND ({base_query})"
        
        print(f"Making API request with query: {base_query}")
        params = {
            'apiKey': NEWS_API_KEY,
            'q': base_query,
            'language': 'ru',
            'pageSize': 100,
            'sortBy': 'publishedAt'
        }
            
        response = requests.get(NEWS_API_URL, params=params)
        print(f"API Response status code: {response.status_code}")
        response.raise_for_status()
        
        news_data = response.json()
        if news_data.get('status') != 'ok':
            error_message = news_data.get('message', 'Unknown error')
            print(f"API Error: {error_message}")
            if 'apiKey' in error_message:
                print("API Key error detected. Please check your NewsAPI key.")
            return []
            
        articles = news_data.get('articles', [])
        print(f"Received {len(articles)} articles from API")
        
        # Фильтрация и обработка статей
        filtered_articles = []
        for article in articles:
            if not article.get('title'):
                continue
                
            # Очистка текстов
            if article.get('content'):
                article['content'] = clean_article_content(article['content'])
            if article.get('description'):
                article['description'] = clean_article_content(article['description'])
                
            # Если нет ни контента, ни описания после очистки
            if not article.get('content') and not article.get('description'):
                continue
                
            # Форматирование даты
            if article.get('publishedAt'):
                try:
                    date = datetime.strptime(article['publishedAt'], '%Y-%m-%dT%H:%M:%SZ')
                    article['publishedAt'] = date.strftime('%d.%m.%Y %H:%M')
                except Exception as e:
                    print(f"Date parsing error: {e}")
                    article['publishedAt'] = None
            
            filtered_articles.append(article)
            
        print(f"After filtering: {len(filtered_articles)} articles")
        return filtered_articles
        
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {e}")
        return []
    except Exception as e:
        print(f"Error: {e}")
        return []

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
        
        sender = app.config.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME')
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
        print(f"SMTP settings: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
        print(f"Using SSL: {app.config.get('MAIL_USE_SSL', False)}, Using TLS: {app.config.get('MAIL_USE_TLS', False)}")
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
                    flash('Инструкции по восстановлению пароля отправлены на вашу почту')
                else:
                    db.session.rollback()
                    flash('Произошла ошибка при отправке email. Пожалуйста, попробуйте позже.')
            except Exception as e:
                db.session.rollback()
                print(f"Database error: {str(e)}")
                flash('Произошла ошибка. Пожалуйста, попробуйте позже.')
        else:
            # Для безопасности не сообщаем, что пользователь не найден
            flash('Если указанный email зарегистрирован, инструкции по восстановлению будут отправлены')
        
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
        login = request.form.get('login')  # Теперь принимаем login вместо email
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
                phone=phone,
                last_login=datetime.utcnow()
            )
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
                        flash('Слишком много попыток входа. Попробуйте позже или восстановите пароль')
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
                        flash('Слишком много попыток входа. Попробуйте позже или восстановите пароль')
                        return render_template('index.html', show_reset=True)
                    else:
                        flash('Неверный пароль!')
            else:
                flash('Пользователь не найден!')

    return render_template('index.html')

@app.route('/news')
def news():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('index'))
    
    category = request.args.get('category', 'general')
    search_query = request.args.get('search', '')
    
    if category not in CATEGORY_NAMES:
        category = 'general'
    
    print(f"Fetching news for category: {category}, search query: {search_query}")
    articles = get_news(category, search_query)
    print(f"Found {len(articles)} articles")
    
    # Получаем текущее время для отображения времени онлайн
    current_time = datetime.utcnow()
    if user.last_login:
        time_online = current_time - user.last_login
        hours_online = time_online.seconds // 3600
        minutes_online = (time_online.seconds % 3600) // 60
    else:
        hours_online = 0
        minutes_online = 0
    
    return render_template(
        'news.html',
        user=user,
        articles=articles,
        categories=CATEGORY_NAMES,
        current_category=category,
        category_name=CATEGORY_NAMES[category],
        hours_online=hours_online,
        minutes_online=minutes_online,
        datetime=datetime
    )

@app.route('/article/<path:article_url>')
def article(article_url):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('index'))
    
    # Получаем параметры из запроса
    category = request.args.get('category', 'general')
    search_query = request.args.get('search', '')
    
    # Получаем все статьи для текущей категории с учетом поискового запроса
    articles = get_news(category, search_query)
    
    # Ищем статью по URL
    article = next((article for article in articles if article['url'] == article_url), None)
    
    if not article:
        flash('Статья не найдена')
        return redirect(url_for('news', category=category, search=search_query))
    
    # Пытаемся получить полный текст статьи
    full_text, publish_date = get_full_article_content(article_url)
    
    if full_text:
        article['content'] = full_text
        if publish_date:
            article['publishedAt'] = publish_date
    elif article.get('description'):
        article['content'] = article['description']
        article['description'] = None
    
    # Если не удалось получить текст
    if not article.get('content'):
        article['content'] = 'К сожалению, полный текст статьи доступен только на сайте источника.'
    
    return render_template('article.html', article=article, user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True) 