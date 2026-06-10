import sqlalchemy
from sqlalchemy import orm
from flask_login import UserMixin

from data.db_session import SqlAlchemyBase


class User(SqlAlchemyBase, UserMixin):
    __tablename__ = 'users'

    id = sqlalchemy.Column(sqlalchemy.Integer,
                           primary_key=True, autoincrement=True)
    email = sqlalchemy.Column(sqlalchemy.String, unique=True, nullable=False)
    hashed_password = sqlalchemy.Column(sqlalchemy.String, nullable=False)
    public_key = sqlalchemy.Column(sqlalchemy.Text, nullable=False)
    encrypted_private_key = sqlalchemy.Column(sqlalchemy.Text, nullable=False)
    nickname = sqlalchemy.Column(sqlalchemy.String, unique=True, nullable=False)
    first_name = sqlalchemy.Column(sqlalchemy.String, nullable=False, default='')
    surname = sqlalchemy.Column(sqlalchemy.String, nullable=False, default='')

    sent_messages = orm.relationship("Message", foreign_keys="Message.sender_id",
                                     back_populates="sender", lazy="dynamic",
                                     cascade="all, delete-orphan")
    received_messages = orm.relationship("Message", foreign_keys="Message.recipient_id",
                                         back_populates="recipient", lazy="dynamic",
                                         cascade="all, delete-orphan")

    def __repr__(self):
        return f'<User> {self.id} {self.nickname}'