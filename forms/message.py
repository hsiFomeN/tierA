from flask_wtf import FlaskForm
from wtforms import TextAreaField, HiddenField, SubmitField
from wtforms.validators import DataRequired

class MessageForm(FlaskForm):
    recipient_id = HiddenField('Получатель', validators=[DataRequired()])
    body = TextAreaField('Текст сообщения', validators=[DataRequired()])
    submit = SubmitField('Отправить')