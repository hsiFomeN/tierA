import datetime
import sqlalchemy
from sqlalchemy import orm

from data.db_session import SqlAlchemyBase


class Message(SqlAlchemyBase):
    __tablename__ = 'messages'

    id = sqlalchemy.Column(sqlalchemy.Integer,
                           primary_key=True, autoincrement=True)
    sender_id = sqlalchemy.Column(sqlalchemy.Integer,
                                  sqlalchemy.ForeignKey('users.id'))
    recipient_id = sqlalchemy.Column(sqlalchemy.Integer,
                                     sqlalchemy.ForeignKey('users.id'))
    encrypted_body = sqlalchemy.Column(sqlalchemy.Text, nullable=False)
    encrypted_copy_for_sender = sqlalchemy.Column(sqlalchemy.Text, nullable=True)
    timestamp = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.utcnow)
    is_read = sqlalchemy.Column(sqlalchemy.Boolean, default=False)
    read_at = sqlalchemy.Column(sqlalchemy.DateTime, nullable=True)

    sender = orm.relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    recipient = orm.relationship("User", foreign_keys=[recipient_id], back_populates="received_messages")

    def __repr__(self):
        return f'<Message> {self.id} from {self.sender_id} to {self.recipient_id}'