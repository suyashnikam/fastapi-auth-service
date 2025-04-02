#!/bin/sh

echo "Waiting for PostgreSQL to start..."
sleep 5  # Wait for Postgres to fully initialize

echo "Running Alembic migrations..."
#alembic init alembic
alembic revision --autogenerate -m "Initial migration"
alembic upgrade head

echo "Starting FastAPI application..."
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
