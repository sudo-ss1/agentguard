FROM python:3.12-slim
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock
COPY . .
# Editable install so lab/ and attacks/ resolve relative to /app.
RUN pip install --no-cache-dir --no-deps -e .
