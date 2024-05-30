from flask import render_template, request, redirect, flash, session, abort, url_for, send_file, current_app
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import io
import mimetypes

from database import app, db, Records, Users, Files, encrypt_data, decrypt_data, cipher_suite


login_manager = LoginManager(app)
login_manager.login_view = 'patient_enter'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


@app.route('/')
def home():
    return render_template("home.html")


@app.route('/information')
def information():
    return render_template("information.html")


@app.route('/patient-registration', methods=['POST', 'GET'])
def patient_registration():
    if request.method == 'POST':
        name = request.form['name']
        login = request.form['login']
        psw = request.form['psw']
        psw2 = request.form['psw2']

        if not name or not login or not psw or not psw2:
            flash('Пожалуйста, заполните все поля.', 'error')
        elif psw != psw2:
            flash('Пароли не совпадают.', 'error')
        elif Users.query.filter_by(login=login).first():
            flash('Пользователь с таким логином уже существует.', 'error')
        else:
            new_user = Users(login=login, psw=generate_password_hash(psw))
            new_user.set_name(name)  # Установка зашифрованного имени
            db.session.add(new_user)
            db.session.commit()
            flash('Вы успешно зарегистрированы!', 'success')
            session['name'] = name  # Сохраняем имя пользователя в сессии
            session['user_id'] = new_user.id  # Сохраняем идентификатор пользователя в сессии
            return redirect(url_for('patient_id'))  # Перенаправляем на страницу patient-id
    return render_template("patient-registration.html")


@app.route('/patient-id')
def patient_id():
    user_id = session.get('user_id')
    if user_id:
        user = Users.query.get(user_id)
        if user:
            user_name = user.get_name()  # Дешифрование имени пользователя
            return render_template("patient-id.html", user=user, user_name=user_name)
    return "Ошибка: Пользователь не найден"


@app.route('/patient-enter', methods=['GET', 'POST'])
def patient_enter():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        remember = 'remember' in request.form
        user = Users.query.filter_by(login=login).first()
        if user and check_password_hash(user.psw, password):
            login_user(user, remember=remember)
            session['user_id'] = user.id  # Сохраняем user_id в сессии
            return redirect('/patient-posts')
        else:
            flash('Неверный логин или пароль.', 'error')  # Сообщение об ошибке
    return render_template("patient-enter.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_id', None)
    flash('Вы вышли из системы.', 'info')
    return redirect('/patient-enter')


@app.route('/doctor-enter', methods=['GET', 'POST'])
def doctor_enter():
    if request.method == 'POST':
        # Получаем данные из формы
        code = request.form['code']
        name = request.form['name']

        # Поиск пользователя по уникальному коду
        user = Users.query.get(code)

        if user and user.get_name() == name:
            # Если пользователь найден и имя совпадает, сохраняем его id в сессии
            session['user_id'] = user.id
            return redirect('/doctor-posts')
        else:
            # Если пользователь не найден или имя не совпадает, выводим сообщение об ошибке
            flash('Пользователь с указанным уникальным кодом и именем не найден.', 'error')

    return render_template("doctor-enter.html")


@app.route('/patient-posts')
@login_required
def patient_posts():
    user_id = session['user_id']
    records = Records.query.filter_by(user_id=user_id).order_by(Records.date.desc()).all()
    for record in records:
        record.text = decrypt_data(record.text)
    return render_template("patient-posts.html", records=records)


@app.route('/doctor-posts', methods=['GET'])
def doctor_posts():
    if request.method == 'GET':
        if 'user_id' in session:
            user_id = session['user_id']
            records = Records.query.filter_by(user_id=user_id).order_by(Records.date.desc()).all()
            for record in records:
                record.text = decrypt_data(record.text)
            return render_template("doctor-posts.html", records=records)
        else:
            flash('Пожалуйста, войдите для просмотра записей пациента.', 'error')
            return redirect('/doctor-enter')

    return render_template("doctor-enter.html")


@app.route('/patient-create-record', methods=['POST', 'GET'])
@login_required
def create_record():
    if request.method == "POST":
        title = request.form['title']
        text = request.form['text']

        if not title:
            flash('Поле "Краткое описание" не может быть пустым.', 'error')
            return redirect('/patient-create-record')

        encrypted_text = encrypt_data(text)
        record = Records(title=title, text=encrypted_text, user_id=current_user.id)

        try:
            db.session.add(record)
            db.session.commit()
            return redirect('/patient-posts')
        except:
            flash('Произошла ошибка при добавлении записи.', 'error')
            return redirect('/patient-create-record')
    else:
        return render_template("patient-create-record.html")


@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/posts/<string:id>/delete')
def delete(id):
    record = Records.query.get_or_404(str(id))

    # Проверяем, является ли текущий пользователь владельцем записи
    if record.user_id != current_user.id:
        abort(403)  # Запрет доступа (Forbidden)

    try:
        db.session.delete(record)
        db.session.commit()
        return redirect('/patient-posts')
    except:
        return "Произошла ошибка при удалении записи"


@app.route('/posts/<string:id>/update', methods=['POST', 'GET'])
def post_update(id):
    record = Records.query.get(str(id))

    # Проверяем, является ли текущий пользователь владельцем записи
    if record.user_id != current_user.id:
        abort(403)  # Запрет доступа (Forbidden)

    if request.method == "POST":
        record.title = request.form['title']
        record.text = encrypt_data(request.form['text'])

        try:
            db.session.commit()
            return redirect('/patient-posts')
        except:
            return "Произошла ошибка при добавлении записи"
    else:
        record.text = decrypt_data(record.text)
        return render_template("patient-post-update.html", record=record)


@app.route('/delete_user/<user_id>')
@login_required
def delete_user(user_id):
    # Проверяем, аутентифицирован ли пользователь и является ли он владельцем удаляемого аккаунта
    if current_user.is_authenticated and current_user.id == user_id:
        # Получаем пользователя по его идентификатору
        user = Users.query.get(user_id)
        if user:
            # Находим и удаляем все записи пользователя
            records = Records.query.filter_by(user_id=user_id).all()
            for record in records:
                db.session.delete(record)

            # Находим и удаляем все файлы пользователя
            files = Files.query.filter_by(user_id=user_id).all()
            for file in files:
                db.session.delete(file)

            # Удаляем пользователя из базы данных
            db.session.delete(user)
            db.session.commit()

            logout_user()  # Выход из учетной записи после удаления
            return redirect('/')
        else:
            return "Пользователь не найден"
    else:
        return "Вы не имеете прав на удаление этого пользователя или не авторизованы для выполнения этой операции"


@app.route('/doctor-files', methods=['GET', 'POST'])
def doctor_files():
    user_id = session['user_id']
    files = Files.query.filter_by(user_id=user_id).all()
    decrypted_files = []

    for file in files:
        decrypted_file = {
            'id': file.id,
            'title': file.title,
            'file_content': file.file_content
        }
        decrypted_files.append(decrypted_file)

    return render_template("doctor-files.html", files=decrypted_files)


@app.route('/patient-files', methods=['GET', 'POST'])
@login_required
def patient_files():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Файл не был выбран', 'danger')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('Файл не был выбран', 'danger')
            return redirect(request.url)

        if file:
            user_id = current_user.id
            file_content = file.read()

            new_record = Files(title=file.filename, file_content=file_content, user_id=user_id)
            db.session.add(new_record)
            db.session.commit()

            flash('Файл успешно загружен', 'success')
            return redirect('/patient-files')

    files = Files.query.filter_by(user_id=current_user.id).all()
    return render_template("patient-files.html", files=files)


@app.route('/file/<int:file_id>')
def download_file(file_id):
    try:
        file = Files.query.get_or_404(file_id)
        mimetype, _ = mimetypes.guess_type(file.title)
        if not mimetype:
            mimetype = 'application/octet-stream'

        return send_file(
            io.BytesIO(file.file_content),
            as_attachment=True,
            download_name=file.title,
            mimetype=mimetype
        )
    except Exception as e:
        current_app.logger.error(f"Error downloading file: {e}")
        abort(500, description="Ошибка скачивания файла.")


@app.route('/file/<file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    file = Files.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        flash('У вас нет прав для удаления этого файла.', 'danger')
        return redirect(url_for('patient_files'))

    db.session.delete(file)
    db.session.commit()
    flash('Файл успешно удалён', 'success')
    return redirect(url_for('patient_files'))


if __name__ == "__main__":
    app.run(debug=False)