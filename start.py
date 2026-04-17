import os
import uvicorn

os.chdir(os.path.dirname(os.path.abspath(__file__)))

from app import app

port = int(os.environ.get("PORT", 8000))


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info",
        reload=False
    )

