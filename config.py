import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get email settings from environment
mail_username = os.environ.get('MAIL_USERNAME')
mail_password = os.environ.get('MAIL_APP_PASSWORD')
news_api_key = os.environ.get('NEWS_API_KEY')

# Print debug information
print(f"\nConfig Debug:")
print(f"MAIL_USERNAME from env: {mail_username}")
print(f"MAIL_PASSWORD set: {'Yes' if mail_password else 'No'}")
print(f"NEWS_API_KEY set: {'Yes' if news_api_key else 'No'}")

# Email Configuration
MAIL_SERVER = 'smtp.mail.ru'
MAIL_PORT = 465
MAIL_USE_TLS = False
MAIL_USE_SSL = True
MAIL_USERNAME = mail_username
MAIL_PASSWORD = mail_password
MAIL_DEFAULT_SENDER = mail_username

# Flask-Mail debug mode
MAIL_DEBUG = True

# NewsAPI Configuration
NEWS_API_KEY = news_api_key

# Другие настройки приложения
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here')

class Config:
    # Базовая директория приложения
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    
    # Конфигурация загрузки файлов
    UPLOAD_FOLDER = os.path.join(BASEDIR, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Максимальный размер файла - 16MB
    ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

    # Конфигурация базы данных
    SQLALCHEMY_DATABASE_URI = 'sqlite:///news.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Настройки пагинации
    POSTS_PER_PAGE = 10 