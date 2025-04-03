# User Service - Pizza Delivery API

## Overview
The **User Service** is a microservice in the Pizza Delivery API system. It is responsible for user authentication, registration, and token management using **FastAPI**, **SQLAlchemy**, and **JWT authentication**. The service is containerized using **Docker** and connects to a **PostgreSQL** database.

## Features
- User Registration (Signup)
- User Login with JWT authentication
- Token Refresh Mechanism
- Database Integration using PostgreSQL
- Dockerized Deployment

## Technologies Used
- **FastAPI** (Backend Framework)
- **SQLAlchemy** (ORM)
- **PostgreSQL** (Database)
- **Docker & Docker Compose** (Containerization)
- **Alembic** (Database Migrations)
- **Pydantic** (Data Validation)
- **JWT Authentication**

---

## Getting Started
### 1. Clone the Repository
```bash
git clone https://github.com/your-username/user-service.git
cd user-service
```

### 2. Set Up Environment Variables
Create a `.env` file in the root directory and define the following variables:
```ini
DATABASE_URL=postgresql+psycopg2://username:password@postgres:5433/user_service
SECRET_KEY= Your_JWT_secrete_key
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_MINUTES=1400
```

### 3. Run the Service Using Docker
#### a) Build and Run the Containers
```bash
docker-compose up --build -d
```

#### b) Run Database Migrations
```bash
docker exec -it user-service-container alembic upgrade head
```

### 4. Access the API Documentation
Once the container is running, you can access the API docs at:
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## API Endpoints
| Endpoint              | Method | Description |
|----------------------|--------|-------------|
| `/signup`           | POST   | User registration |
| `/login`            | POST   | User login and token generation |
| `/refresh`          | POST   | Refresh access token |

---

## Database Migrations
If you make any changes to your models, run the following command to create a new migration:
```bash
docker exec -it user-service-container alembic revision --autogenerate -m "migration message"
docker exec -it user-service-container alembic upgrade head
```

---

## Stopping the Service
To stop the running containers:
```bash
docker-compose down
```

## License
This project is licensed under the MIT License.

---

## Author
**Suyash Nikam**  
[GitHub](https://github.com/suyashnikam) | [LinkedIn](https://www.linkedin.com/in/suyash-nikam/)

