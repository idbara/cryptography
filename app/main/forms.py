from flask import url_for
from flask_wtf import FlaskForm
from wtforms import ValidationError
from wtforms.fields import (
    BooleanField,
    PasswordField,
    StringField,
    SubmitField,
    SelectField,
)
from wtforms.validators import Email, EqualTo, InputRequired, Length, DataRequired

class ReverseEncryptForm(FlaskForm):
    plaintext = StringField(
        'PlainText')
    encrypt = SubmitField('Encrypt')

class ReverseDecryptForm(FlaskForm):
    ciphertext = StringField(
        'CipherText')
    decrypt = SubmitField('Decrypt')

class Rot13EncryptForm(FlaskForm):
    plaintext = StringField(
        'PlainText')
    encrypt = SubmitField('Encrypt')

class Rot13DecryptForm(FlaskForm):
    ciphertext = StringField(
        'CipherText')
    decrypt = SubmitField('Decrypt')