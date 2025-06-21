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