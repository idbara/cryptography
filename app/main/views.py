from flask import Blueprint, render_template
from app.module import caesarcipher, reversecipher, rot13, reverserot13encrypt, reverserot13decrypt

from app.main.forms import (
    ReverseEncryptForm,
    ReverseDecryptForm
)

from app import socketio

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('main/index.html')

@main.route('/reverse', methods=['GET', 'POST'])
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