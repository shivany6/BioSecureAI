from database import engine
from models import Base

# Import all models so SQLAlchemy knows about them
import models

Base.metadata.create_all(bind=engine)

print("Database tables created successfully!")
