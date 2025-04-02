from pydantic import BaseSettings
import os

class Settings(BaseSettings):
    authjwt_secret_key: str = os.getenv('SECRET_KEY')
    authjwt_algorithm: str = os.getenv('JWT_ALGORITHM')

    class Config:
        env_file = ".env"  # Optional: if you're using an .env file for environment variables
