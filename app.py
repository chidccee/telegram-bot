from flask import Flask, request
import telebot
import tensorflow as tf
import numpy as np
import os
import sqlite3
import bcrypt
import requests
from tensorflow.keras.preprocessing import image
import json

# Инициализация Flask и Telegram-бота
app = Flask(__name__)
TOKEN = '7833441724:AAHh_rQQsDhh7lpwUPEC300zFbD_yYc3c5Y'
bot = telebot.TeleBot(TOKEN, threaded=False)
WEBHOOK_URL = 'https://<your-username>.pythonanywhere.com/webhook'  # Замените на ваш URL

# Инициализация модели
model = tf.keras.models.Sequential([
    tf.keras.layers.Conv2D(32, (3,3), activation='relu', input_shape=(200,200,3)),
    tf.keras.layers.MaxPooling2D(2,2),
    tf.keras.layers.Conv2D(64, (3,3), activation='relu'),
    tf.keras.layers.MaxPooling2D(2,2),
    tf.keras.layers.Flatten(),
    tf.keras.layers.Dense(128, activation='relu'),
    tf.keras.layers.Dense(1, activation='sigmoid')
])
model.compile(optimizer=tf.keras.optimizers.Adam(),
              loss='binary_crossentropy',
              metrics=['accuracy'])
model.load_weights('best_weights.h5')
print("Веса модели успешно загружены!")

# Инициализация базы данных SQLite
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 chat_id INTEGER PRIMARY KEY,
                 password TEXT NOT NULL,
                 is_logged_in BOOLEAN DEFAULT FALSE,
                 prediction_count INTEGER DEFAULT 0,
                 is_admin BOOLEAN DEFAULT FALSE,
                 username TEXT
                 )''')
    conn.commit()
    conn.close()

init_db()

# Состояния пользователей
user_states = {}
ADMIN_SECRET = "admin_secret"

# Вспомогательные функции для базы данных
def register_user(chat_id, password, username=None):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO users (chat_id, password, username) VALUES (?, ?, ?)",
              (chat_id, hashed_password.decode('utf-8'), username))
    conn.commit()
    conn.close()

def check_password(chat_id, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE chat_id = ?", (chat_id,))
    result = c.fetchone()
    conn.close()
    if result:
        return bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8'))
    return False

def set_login_status(chat_id, status):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET is_logged_in = ? WHERE chat_id = ?", (status, chat_id))
    conn.commit()
    conn.close()

def increment_prediction_count(chat_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET prediction_count = prediction_count + 1 WHERE chat_id = ?", (chat_id,))
    conn.commit()
    conn.close()

def is_user_registered(chat_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE chat_id = ?", (chat_id,))
    result = c.fetchone()
    conn.close()
    return result is not None

def is_user_logged_in(chat_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT is_logged_in FROM users WHERE chat_id = ?", (chat_id,))
    result = c.fetchone()
    conn.close()
    return result and result[0]

def is_admin(chat_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT is_admin FROM users WHERE chat_id = ?", (chat_id,))
    result = c.fetchone()
    conn.close()
    return result and result[0]

def get_user_list():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT chat_id, username, prediction_count, is_admin FROM users")
    users = c.fetchall()
    conn.close()
    return users

def delete_user(chat_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE chat_id = ?", (chat_id,))
    conn.commit()
    conn.close()

def make_admin(chat_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET is_admin = TRUE WHERE chat_id = ?", (chat_id,))
    conn.commit()
    conn.close()

# Функция отправки сообщения через API
def send_message(chat_id, text):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text
    }
    requests.post(url, json=payload)

# Обработка изображения
def predict_image(img_path):
    img = image.load_img(img_path, target_size=(200, 200))
    x = image.img_to_array(img)
    x = np.expand_dims(x, axis=0)
    x = x / 255.0
    prediction = model.predict(x)
    confidence = prediction[0][0] * 100 if prediction[0] >= 0.5 else (1 - prediction[0][0]) * 100
    if prediction[0] < 0.5:
        return "панда 🐼", (1 - prediction[0][0]) * 100
    else:
        return "человек 👤", prediction[0][0] * 100

# Обработчик webhook
@app.route('/webhook', methods=['POST'])
def webhook():
    update = request.get_json()
    if 'message' not in update:
        return 'OK', 200

    message = update['message']
    chat_id = message['chat']['id']

    # Обработка текстовых сообщений
    if 'text' in message:
        text = message['text']
        
        # Обработка команд
        if text == '/start':
            send_message(chat_id, "Привет! Я бот для распознавания панд и людей 🐼👤.\nДоступные команды:\n/register\n/login\n/predict\n/logout\n/makeadmin")
        elif text == '/register':
            user_states[chat_id] = 'registering'
            send_message(chat_id, "Введите пароль для регистрации:")
        elif text == '/login':
            user_states[chat_id] = 'logging_in'
            send_message(chat_id, "Введите пароль для входа:")
        elif text == '/logout':
            if is_user_registered(chat_id):
                set_login_status(chat_id, False)
                send_message(chat_id, "Вы вышли из системы.")
            else:
                send_message(chat_id, "Вы не зарегистрированы.")
        elif text == '/predict':
            if not is_user_registered(chat_id) or not is_user_logged_in(chat_id):
                send_message(chat_id, "Сначала выполните /login!")
            else:
                send_message(chat_id, "Отправьте картинку для распознавания.")
        elif text == '/makeadmin':
            user_states[chat_id] = 'making_admin'
            send_message(chat_id, "Введите секретный код для назначения администратора:")
        elif text.startswith('/list_users'):
            if not is_admin(chat_id):
                send_message(chat_id, "Эта команда доступна только администраторам.")
            else:
                users = get_user_list()
                if not users:
                    send_message(chat_id, "Пользователи отсутствуют.")
                else:
                    response = "Список пользователей:\n"
                    for user in users:
                        role = "Админ" if user[3] else "Пользователь"
                        username = user[1] if user[1] else "Не указано"
                        response += f"ID: {user[0]}, Имя: {username}, Предсказания: {user[2]}, Роль: {role}\n"
                    send_message(chat_id, response)
        elif text.startswith('/delete_user'):
            if not is_admin(chat_id):
                send_message(chat_id, "Эта команда доступна только администраторам.")
            else:
                try:
                    target_chat_id = int(text.split()[1])
                    if is_user_registered(target_chat_id):
                        delete_user(target_chat_id)
                        send_message(chat_id, f"Пользователь {target_chat_id} удален.")
                    else:
                        send_message(chat_id, "Пользователь не найден.")
                except (IndexError, ValueError):
                    send_message(chat_id, "Использование: /delete_user <chat_id>")
        elif text.startswith('/add_admin'):
            if not is_admin(chat_id):
                send_message(chat_id, "Эта команда доступна только администраторам.")
            else:
                try:
                    target_chat_id = int(text.split()[1])
                    if is_user_registered(target_chat_id):
                        make_admin(target_chat_id)
                        send_message(chat_id, f"Пользователь {target_chat_id} назначен администратором.")
                    else:
                        send_message(chat_id, "Пользователь не найден.")
                except (IndexError, ValueError):
                    send_message(chat_id, "Использование: /add_admin <chat_id>")
        # Обработка текстовых сообщений в зависимости от состояния
        elif chat_id in user_states:
            state = user_states[chat_id]
            if state == 'registering':
                password = text
                username = message['from'].get('username')
                register_user(chat_id, password, username)
                user_states.pop(chat_id)
                send_message(chat_id, "Регистрация успешна! Теперь войдите через /login.")
            elif state == 'logging_in':
                password = text
                if check_password(chat_id, password):
                    set_login_status(chat_id, True)
                    send_message(chat_id, "Вход выполнен успешно! Теперь можете использовать /predict.")
                else:
                    send_message(chat_id, "Неверный пароль. Попробуйте снова через /login.")
                user_states.pop(chat_id)
            elif state == 'making_admin':
                if text == ADMIN_SECRET:
                    if is_user_registered(chat_id):
                        make_admin(chat_id)
                        send_message(chat_id, "Вы назначены администратором!")
                    else:
                        send_message(chat_id, "Сначала зарегистрируйтесь через /register.")
                else:
                    send_message(chat_id, "Неверный код.")
                user_states.pop(chat_id)

    # Обработка фотографий
    if 'photo' in message:
        if not is_user_registered(chat_id) or not is_user_logged_in(chat_id):
            send_message(chat_id, "Сначала выполните /login, чтобы использовать /predict.")
            return 'OK', 200

        file_id = message['photo'][-1]['file_id']
        file_info = bot.get_file(file_id)
        file_url = f"https://api.telegram.org/file/bot{TOKEN}/{file_info.file_path}"
        img_path = f"temp_{chat_id}.jpg"

        # Скачивание файла
        response = requests.get(file_url)
        with open(img_path, 'wb') as f:
            f.write(response.content)

        try:
            prediction, confidence = predict_image(img_path)
            increment_prediction_count(chat_id)
            send_message(chat_id, f"На изображении: {prediction} (вероятность: {confidence:.2f}%)")
        except Exception as e:
            send_message(chat_id, f"Ошибка при распознавании: {str(e)}")

        if os.path.exists(img_path):
            os.remove(img_path)

    return 'OK', 200

# Регистрация webhook
def set_webhook():
    url = f"https://api.telegram.org/bot{TOKEN}/setWebhook"
    payload = {"url": WEBHOOK_URL}
    response = requests.post(url, json=payload)
    print(f"Webhook registration: {response.json()}")

if __name__ == '__main__':
    set_webhook()  # Регистрируем webhook при запуске
    app.run(debug=True)