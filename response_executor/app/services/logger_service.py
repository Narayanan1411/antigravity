from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime
)

from sqlalchemy.orm import (
    declarative_base,
    sessionmaker
)

from datetime import datetime


DATABASE_URL = "sqlite:///response_engine.db"

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(
    bind=engine
)

Base = declarative_base()


class EventLog(Base):

    __tablename__ = "event_logs"

    id = Column(Integer, primary_key=True)

    action = Column(String)

    target = Column(String)

    status = Column(String)

    message = Column(String)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow
    )


Base.metadata.create_all(bind=engine)


class LoggerService:

    def log_event(
        self,
        action,
        target,
        status,
        message
    ):

        db = SessionLocal()

        log = EventLog(
            action=action,
            target=target,
            status=status,
            message=message
        )

        db.add(log)

        db.commit()

        db.close()

    def get_logs(self):

        db = SessionLocal()

        logs = db.query(EventLog).all()

        db.close()

        return logs