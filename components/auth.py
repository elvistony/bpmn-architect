from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
from components.config import LOGIN_METHOD, AUTH_CREDENTIALS

security = HTTPBasic(auto_error=False)

'''
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
'''

from fastapi import Request, HTTPException, Depends 
from fastapi.security import HTTPBasicCredentials 
import secrets 
import win32security 
import win32api 

def get_current_user( request: Request, credentials: HTTPBasicCredentials = Depends(security) ): 
    if LOGIN_METHOD == "iis-header": 
        token_handle_str = request.headers.get("X-IIS-WindowsAuthToken") 
        if not token_handle_str: 
            raise HTTPException( 
            status_code=401, 
            detail="Missing X-IIS-WindowsAuthToken header" 
            ) 

    try: 
        # Convert hex string to HANDLE 
        token_handle = int(token_handle_str, 16) 

        # Get SID from token 
        sid = win32security.GetTokenInformation( 
        token_handle, 
        win32security.TokenUser 
        )[0] 

        # Resolve SID to DOMAIN\\User 
        user, domain, _ = win32security.LookupAccountSid(None, sid) 

        return f"{domain}\\{user}" 

    except Exception as exc: 
        raise HTTPException( 
        status_code=401, 
        detail=f"Invalid Windows auth token: {exc}" 
        ) 

    finally: 
        try: 
            win32api.CloseHandle(token_handle) 
        except Exception: 
            pass 

    # ----------------------------- 
    # Basic auth fallback 
    # ----------------------------- 
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

        is_correct_username = secrets.compare_digest( 
        credentials.username.encode("utf8"), 
        expected_u.encode("utf8"), 
        ) 
        is_correct_password = secrets.compare_digest( 
        credentials.password.encode("utf8"), 
        expected_p.encode("utf8"), 
        ) 

    if not (is_correct_username and is_correct_password): 
        raise HTTPException( 
        status_code=401, 
        detail="Incorrect username or password", 
        headers={"WWW-Authenticate": "Basic"}, 
        ) 

    return credentials.username