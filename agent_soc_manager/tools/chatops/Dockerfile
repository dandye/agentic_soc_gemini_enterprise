# Use a slim Python base matching the repo target (pyproject: py312)
FROM python:3.12-slim

# Set environment variables
ENV HOST=0.0.0.0
ENV PORT=8080
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only the dedicated requirements for this component
# This matches the new requirements.txt we just created
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the ChatOps Python files.
# We skip the entire soc_agent/ folder to keep the container small.
COPY webhook_handler.py chat_app_handler.py chat_api.py security.py decision.py audit.py ./

# Expose the standard Cloud Run port
EXPOSE 8080

# Run the app. chat_app_handler serves /chat/events, /tasks/execute, and
# the legacy /action route (webhook_handler.py kept for rollback).
CMD ["uvicorn", "chat_app_handler:app", "--host", "0.0.0.0", "--port", "8080"]
