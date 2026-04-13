from fastapi import FastAPI, Depends, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import secrets
import os
import shutil

from components.database import engine, get_db, Base
from components.models import Diagram
from components.config import (
    CUSTOM_LOGO, CUSTOM_SUBTITLE, CONTACT_EMAIL, DIAGRAM_STORAGE_PATH, 
    HEARTBEAT_FREQUENCY_SEC, BPMN_TEMPLATES_PATH, IDLE_TIMEOUT_MIN
)
from components.auth import get_current_user

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Live BPMN Editor")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

static_dir = os.path.join(BASE_DIR, "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

templates_dir = os.path.join(BASE_DIR, "templates")
os.makedirs(templates_dir, exist_ok=True)
templates = Jinja2Templates(directory=templates_dir)

# Add config global variables to templates
templates.env.globals['CUSTOM_LOGO'] = CUSTOM_LOGO
templates.env.globals['CUSTOM_SUBTITLE'] = CUSTOM_SUBTITLE
templates.env.globals['CONTACT_EMAIL'] = CONTACT_EMAIL
templates.env.globals['HEARTBEAT_FREQUENCY_SEC'] = HEARTBEAT_FREQUENCY_SEC
templates.env.globals['IDLE_TIMEOUT_MIN'] = IDLE_TIMEOUT_MIN

def generate_nano_id(length=10):
    return secrets.token_urlsafe(length)[:length].replace("-", "A").replace("_", "B")

# -----------------
# FRONTEND ROUTES
# -----------------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request=request, name="landing.html", context={"request": request})

@app.get("/app/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    # Fetch diagrams
    diagrams = db.query(Diagram).all()
    # List templates
    target_templates = [f.name for f in BPMN_TEMPLATES_PATH.glob("*.bpmn")]
    return templates.TemplateResponse(request=request, name="dashboard.html", context={
        "request": request,
        "diagrams": diagrams,
        "templates": target_templates,
        "current_user": current_user
    })

@app.post("/app/new/")
def create_diagram(
    friendly_name: str = Form(...),
    project_name: str = Form(""),
    project_description: str = Form(""),
    template_file: str = Form(""),
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    nano_id = generate_nano_id()
    
    # Copy template to storage path or fallback to empty template
    target_file = DIAGRAM_STORAGE_PATH / f"{nano_id}.bpmn"
    if template_file:
        source_template = BPMN_TEMPLATES_PATH / template_file
        if source_template.exists():
            shutil.copy2(source_template, target_file)
        else:
            with open(target_file, "w") as f:
                f.write('<?xml version="1.0" encoding="UTF-8"?><bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL" id="Definitions_1" targetNamespace="http://bpmn.io/schema/bpmn"></bpmn:definitions>')
    else:
        with open(target_file, "w") as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?><bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL" id="Definitions_1" targetNamespace="http://bpmn.io/schema/bpmn"></bpmn:definitions>')

    new_diagram = Diagram(
        id=nano_id,
        friendly_name=friendly_name,
        project_name=project_name,
        project_description=project_description,
        author_username=current_user,
        last_edited_by=current_user
    )
    db.add(new_diagram)
    db.commit()

    return RedirectResponse(url=f"/app/{nano_id}/edit", status_code=303)

@app.get("/app/{id}/view", response_class=HTMLResponse)
def view_diagram(id: str, request: Request, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    diagram = db.query(Diagram).filter(Diagram.id == id).first()
    if not diagram or getattr(diagram, 'is_deleted', False):
        raise HTTPException(status_code=404, detail="Diagram not found or deleted")
    return templates.TemplateResponse(request=request, name="viewer.html", context={
        "request": request, "diagram": diagram, "current_user": current_user
    })

@app.get("/app/{id}/edit", response_class=HTMLResponse)
def edit_diagram(id: str, request: Request, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    diagram = db.query(Diagram).filter(Diagram.id == id).first()
    if not diagram or getattr(diagram, 'is_deleted', False):
        raise HTTPException(status_code=404, detail="Diagram not found or deleted")
        
    return templates.TemplateResponse(request=request, name="editor.html", context={
        "request": request, "diagram": diagram, "current_user": current_user
    })

@app.get("/embed/{id}/", response_class=HTMLResponse)
def embed_diagram(id: str, request: Request, db: Session = Depends(get_db)):
    # Embed is explicitly unauthenticated for easy intranet embedding
    diagram = db.query(Diagram).filter(Diagram.id == id).first()
    if not diagram or getattr(diagram, 'is_deleted', False):
        raise HTTPException(status_code=404, detail="Diagram not found or deleted")
    return templates.TemplateResponse(request=request, name="embed.html", context={
        "request": request, "diagram": diagram
    })

# -----------------
# API ROUTES
# -----------------

@app.get("/api/diagrams")
def api_get_diagrams(db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    diagrams = db.query(Diagram).all()
    # Check natural lock expiration here so frontend gets accurate data
    now = datetime.utcnow()
    res = []
    for d in diagrams:
        is_locked = bool(d.locked_by and d.lock_expires_at and d.lock_expires_at > now)
        res.append({
            "id": d.id, 
            "project_name": d.project_name,
            "friendly_name": d.friendly_name, 
            "author": d.author_username, 
            "locked_by": d.locked_by if is_locked else None,
            "is_deleted": getattr(d, 'is_deleted', False),
            "last_edited_by": getattr(d, 'last_edited_by', None)
        })
    return res

# -----------------
# ADMIN ROUTES
# -----------------
from components.config import ADMINS

@app.get("/admin/", response_class=HTMLResponse)
def get_admin_dashboard(request: Request, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    if current_user not in ADMINS:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    diagrams = db.query(Diagram).order_by(Diagram.updated_at.desc()).all()
    
    templates_list = []
    if BPMN_TEMPLATES_PATH.exists():
        templates_list = [f.name for f in BPMN_TEMPLATES_PATH.glob("*.bpmn")]

    return templates.TemplateResponse(request=request, name="dashboard.html", context={
        "request": request, 
        "diagrams": diagrams, 
        "current_user": current_user,
        "templates": templates_list,
        "is_admin": True
    })

@app.post("/api/diagram/{id}/unlock")
def force_unlock(id: str, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    if current_user not in ADMINS:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    diagram = db.query(Diagram).filter(Diagram.id == id).first()
    if not diagram:
        raise HTTPException(status_code=404, detail="Diagram not found")
        
    diagram.locked_by = None
    diagram.lock_expires_at = None
    db.commit()
    return {"status": "unlocked"}

@app.post("/api/diagram/{id}/restore")
def restore_diagram(id: str, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    if current_user not in ADMINS:
        raise HTTPException(status_code=403, detail="Admin access required")
        
    diagram = db.query(Diagram).filter(Diagram.id == id).first()
    if not diagram:
        raise HTTPException(status_code=404, detail="Diagram not found")
        
    diagram.is_deleted = False
    diagram.last_edited_by = current_user
    diagram.updated_at = datetime.utcnow()
    db.commit()
    return {"status": "restored"}

@app.post("/api/diagram/{id}/delete")
def delete_diagram(id: str, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    diagram = db.query(Diagram).filter(Diagram.id == id).first()
    if not diagram:
        raise HTTPException(status_code=404, detail="Diagram not found")
        
    diagram.is_deleted = True
    diagram.last_edited_by = current_user
    diagram.updated_at = datetime.utcnow()
    diagram.locked_by = None
    diagram.lock_expires_at = None
    db.commit()
    return {"status": "deleted"}

@app.get("/api/diagram/{id}/xml")
def api_get_xml(id: str, request: Request, db: Session = Depends(get_db)): 
    # Must be unauthenticated for embed view to work, or at least open 
    file_path = DIAGRAM_STORAGE_PATH / f"{id}.bpmn"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found on disk")
    with open(file_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), media_type="application/xml")

@app.post("/api/diagram/{id}/save")
async def api_save_xml(id: str, request: Request, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    diagram = db.query(Diagram).filter(Diagram.id == id).first()
    if not diagram or getattr(diagram, 'is_deleted', False):
        raise HTTPException(status_code=404, detail="Diagram not found or deleted")
        
    now = datetime.utcnow()
    # If locked by someone else and lock hasn't expired
    if diagram.locked_by and diagram.locked_by != current_user:
        if diagram.lock_expires_at and diagram.lock_expires_at > now:
            raise HTTPException(status_code=403, detail="File is locked by another user")
            
    payload = await request.body()
    
    file_path = DIAGRAM_STORAGE_PATH / f"{id}.bpmn"
    temp_path = DIAGRAM_STORAGE_PATH / f"{id}.tmp"
    with open(temp_path, "wb") as f:
        f.write(payload)
    os.replace(temp_path, file_path) 
    
    diagram.last_edited_by = current_user
    diagram.updated_at = now
    db.commit()
    return {"status": "success"}

@app.post("/api/diagram/{id}/heartbeat")
def api_heartbeat(id: str, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    now = datetime.utcnow()
    expires = now + timedelta(seconds=HEARTBEAT_FREQUENCY_SEC + 10) # Pad by 10s
    
    diagram = db.query(Diagram).filter(Diagram.id == id).first()
    if not diagram or getattr(diagram, 'is_deleted', False):
        raise HTTPException(status_code=404, detail="Diagram not found or deleted")
        
    if diagram.locked_by == current_user:
        diagram.lock_expires_at = expires
        db.commit()
        return {"status": "extended", "locked_by": current_user}
    elif not diagram.locked_by or (diagram.lock_expires_at and diagram.lock_expires_at < now):
        diagram.locked_by = current_user
        diagram.lock_expires_at = expires
        db.commit()
        return {"status": "acquired", "locked_by": current_user}
    else:
        raise HTTPException(status_code=409, detail=f"Locked by {diagram.locked_by}")

@app.post("/api/diagram/{id}/release")
def api_release(id: str, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    diagram = db.query(Diagram).filter(Diagram.id == id).first()
    if not diagram:
        raise HTTPException(status_code=404, detail="Diagram not found")
    if diagram.locked_by == current_user:
        diagram.locked_by = None
        diagram.lock_expires_at = None
        db.commit()
    return {"status": "released"}

from pydantic import BaseModel
class DiagramMetadata(BaseModel):
    project_name: str
    friendly_name: str
    project_description: str

@app.post("/api/diagram/{id}/metadata")
def update_metadata(id: str, payload: DiagramMetadata, db: Session = Depends(get_db)):
    diagram = db.query(Diagram).filter(Diagram.id == id).first()
    if not diagram or getattr(diagram, 'is_deleted', False):
        raise HTTPException(status_code=404, detail="Diagram not found or deleted")
        
    diagram.project_name = payload.project_name
    diagram.friendly_name = payload.friendly_name
    diagram.project_description = payload.project_description
    diagram.updated_at = datetime.utcnow()
    db.commit()
    return {"status": "success"}

@app.post("/api/diagram/{id}/delete")
def delete_diagram(id: str, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    diagram = db.query(Diagram).filter(Diagram.id == id).first()
    if not diagram or getattr(diagram, 'is_deleted', False):
        raise HTTPException(status_code=404, detail="Diagram not found")
        
    diagram.is_deleted = True
    diagram.last_edited_by = current_user
    diagram.updated_at = datetime.utcnow()
    db.commit()
    return {"status": "deleted"}
