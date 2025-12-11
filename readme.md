# OBDM Middleware

OBDM Middleware is a Python-based API service that acts as an
intermediary between **OBDM Frontend** (Vue.js) and the **Apache Ambari
API backend**. It provides secure, structured REST endpoints while
handling CORS, API authentication, request forwarding, data
transformation, and centralized business logic.

This application is built using **Flask**, **Flask-RESTful**, and
**SQLAlchemy**, and is fully containerized using Docker.

------------------------------------------------------------------------

## 🚀 Features

-   Acts as a secure middleware between obdm frontend and Ambari API
-   Built with **Flask 3.1.0** and **Flask-RESTful**
-   JWT-based authentication (PyJWT)
-   Supports CORS
-   Database support using SQLAlchemy
-   Environment variable configuration via python-dotenv
-   Production-ready deployment using **Gunicorn**
-   Fully Dockerized

------------------------------------------------------------------------

## 📦 Technologies & Dependencies

All dependencies are defined in `requirements.txt`:

    aniso8601==9.0.1
    blinker==1.9.0
    click==8.1.7
    colorama==0.4.6
    Flask==3.1.0
    Flask-RESTful==0.3.10
    Flask-SQLAlchemy==3.1.1
    itsdangerous==2.2.0
    Jinja2==3.1.4
    MarkupSafe==3.0.2
    pytz==2024.2
    six==1.17.0
    SQLAlchemy==2.0.36
    typing_extensions==4.12.2
    Werkzeug==3.1.3
    flask-cors
    gunicorn
    PyJWT==2.9.0
    requests
    python-dotenv
    cryptography

------------------------------------------------------------------------

## 📁 Project Structure

    obdm-middleware/
    ├─ app/
    │  ├─ __init__.py
    │  ├─ api_client.py
    │  ├─ auth.py
    │  ├─ app.py
    │  ├─ config.py
    │  └─ routes.py
    ├─ .env
    ├─ Dockerfile
    ├─ docker-compose.yaml
    ├─ requirements.txt
    └─ README.md

------------------------------------------------------------------------

## 🛠️ Local Development

### 1. Create Python Virtual Environment

    python -m venv venv
    source venv/bin/activate  # Linux/Mac
    venv\Scripts\activate     # Windows

### 2. Install Dependencies

    pip install -r requirements.txt

### 3. Run Development Server

    flask run --host=0.0.0.0 --port=5000

If using a `main.py` entry point:

    python app/main.py

------------------------------------------------------------------------

## ⚙️ Environment Variables (`.env`)

    SECRET_KEY=your-secret-key
    AMBARI_API_URL=http://your-ambari-host:8080/api/v1
    JWT_EXPIRE_HOURS=2
    DB_URL=sqlite:///data.db

------------------------------------------------------------------------

## 🐳 Docker Deployment

### Dockerfile (Production)

    FROM python:3.11-slim
    WORKDIR /app
    COPY requirements.txt ./
    RUN pip install --no-cache-dir -r requirements.txt
    COPY . .
    ENV FLASK_APP=app/main.py
    EXPOSE 5000
    CMD ["gunicorn", "-b", "0.0.0.0:5000", "app.main:app"]

### docker-compose.yaml

    services:
      obdm-middleware:
        build: .
        container_name: obdm-middleware
        env_file: .env
        ports:
          - "5000:5000"
        volumes:
          - ./:/app
        restart: unless-stopped

Run it:

    docker compose up --build -d

------------------------------------------------------------------------

## 🔄 Development with Auto-Reload in Docker

    volumes:
      - ./:/app

Enable Flask debug:

    FLASK_ENV=development
    FLASK_DEBUG=1

------------------------------------------------------------------------

## 🔧 Troubleshooting

### Middleware not connecting to Ambari

-   Check `AMBARI_API_URL`
-   Test Ambari API from inside container

### CORS Issues

    from flask_cors import CORS
    CORS(app)

### JWT issues

-   Check expiration
-   Validate timezone

### Need full rebuild?

    docker compose down -v

------------------------------------------------------------------------

## 📄 License

This middleware is part of the OBDM application stack and licensed for
internal usage.
