from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
from components.config import LOGIN_METHOD, AUTH_CREDENTIALS

security = HTTPBasic(auto_error=False)

def get_current_user(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    if LOGIN_METHOD == "iis-header":
        user = request.headers.get("X-Forwarded-User")
        if not user:
            raise HTTPException(status_code=401, detail="Missing X-Forwarded-User header")
        return user
    else:
        # username,password based login
        try:
            expected_u, expected_p = AUTH_CREDENTIALS.split(",", 1)
        except ValueError:
            expected_u, expected_p = "admin", "password"
            
        if not credentials:
            raise HTTPException(
                status_code=401,
                detail="Unauthorized",
                headers={"WWW-Authenticate": "Basic"},
            )
            
        current_username_bytes = credentials.username.encode("utf8")
        correct_username_bytes = expected_u.encode("utf8")
        is_correct_username = secrets.compare_digest(current_username_bytes, correct_username_bytes)
        
        current_password_bytes = credentials.password.encode("utf8")
        correct_password_bytes = expected_p.encode("utf8")
        is_correct_password = secrets.compare_digest(current_password_bytes, correct_password_bytes)
        
        if not (is_correct_username and is_correct_password):
            raise HTTPException(
                status_code=401,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Basic"},
            )
        return credentials.username
