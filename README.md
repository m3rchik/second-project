# Новостной агрегатор

Веб-приложение на Flask для агрегации и просмотра новостей с возможностью создания аккаунта, сохранения избранных статей и просмотра истории.

## Требования

- Python 3.10 или выше
- pip (менеджер пакетов Python)

## Установка

1. Клонируйте репозиторий:
```bash
git clone <your-repository-url>
cd <repository-name>
```

2. Установите зависимости:
```bash
pip install -r requirements.txt
```

3. Создайте файл .env на основе .env.example и заполните необходимые переменные окружения:
```bash
cp .env.example .env
# Отредактируйте .env файл, добавив свои значения
```

4. Инициализируйте базу данных:
```bash
flask db upgrade
```

## Запуск для разработки

```bash
flask run --debug
```

## Развертывание

### PythonAnywhere

1. Создайте аккаунт на PythonAnywhere
2. Загрузите код через Git или вручную
3. Создайте виртуальное окружение и установите зависимости
4. Настройте WSGI файл для использования gunicorn
5. Настройте переменные окружения в разделе Variables
6. Перезапустите веб-приложение

### Heroku

1. Установите Heroku CLI
2. Войдите в аккаунт:
```bash
heroku login
```

3. Создайте приложение:
```bash
heroku create your-app-name
```

4. Настройте переменные окружения:
```bash
heroku config:set SECRET_KEY=your-secret-key
heroku config:set MAIL_USERNAME=your-email@mail.ru
heroku config:set MAIL_APP_PASSWORD=your-mail-app-password
heroku config:set NEWS_API_KEY=your-newsapi-key
```

5. Разверните приложение:
```bash
git push heroku main
```

## Переменные окружения

- `SECRET_KEY`: Секретный ключ для Flask
- `MAIL_USERNAME`: Email адрес для отправки писем
- `MAIL_APP_PASSWORD`: Пароль приложения для почты
- `NEWS_API_KEY`: API ключ от NewsAPI.org 