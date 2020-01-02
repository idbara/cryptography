from flask import Blueprint, render_template
from app.module import caesarcipher, reversecipher, rot13, reverserot13encrypt, reverserot13decrypt

from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user,
)

from app.main.forms import (
    ReverseEncryptForm,
    ReverseDecryptForm,
    Rot13EncryptForm,
    Rot13DecryptForm
)

from app import socketio

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('main/index.html')

@main.route('/reverse', methods=['GET', 'POST'])
@login_required
def reverse():
    encrypt =''
    decrypt =''
    form = ReverseEncryptForm()
    form2 = ReverseDecryptForm()
    if form.validate_on_submit():
        text = form.plaintext.data
        encrypt = reversecipher(text)
    if form2.validate_on_submit():
        text = form2.ciphertext.data
        decrypt = reversecipher(text)
    return render_template('main/reverse.html', form=form, form2=form2, encrypt=encrypt,decrypt=decrypt)

@main.route('/rot13', methods=['GET', 'POST'])
@login_required
def rot13():
    encrypt =''
    decrypt =''
    form = Rot13EncryptForm()
    form2 = Rot13DecryptForm()
    if form.validate_on_submit():
        text = form.plaintext.data
        encrypt = rot13(text)
    if form2.validate_on_submit():
        text = form2.ciphertext.data
        decrypt = rot13(text)
    return render_template('main/rot13.html', form=form, form2=form2, encrypt=encrypt,decrypt=decrypt)