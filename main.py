from fastapi import FastAPI
from fastapi_jwt_auth import AuthJWT
import auth_routes
from config import Settings

app = FastAPI()


@AuthJWT.load_config
def get_config():
    return Settings()

app.include_router(auth_routes.auth_router)
