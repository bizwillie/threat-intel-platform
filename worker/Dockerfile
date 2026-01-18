FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy worker code
COPY . .

# Create upload directory
RUN mkdir -p /app/uploads

# Run Celery worker
CMD ["celery", "-A", "celery_app", "worker", "--loglevel=info", "--queues=intel"]
