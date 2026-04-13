from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.sql import func
from components.database import Base

class Diagram(Base):
    __tablename__ = "diagrams"

    id = Column(String(12), primary_key=True, index=True) # NanoID
    friendly_name = Column(String(255), nullable=False)
    project_name = Column(String(255), nullable=False, default="BPMN Project")
    project_description = Column(String(1000), nullable=True)
    author_username = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    locked_by = Column(String(100), nullable=True)
    last_edited_by = Column(String(100), nullable=True)
    lock_expires_at = Column(DateTime(timezone=True), nullable=True)
    is_deleted = Column(Boolean, default=False)
