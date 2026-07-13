FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# non-root
RUN useradd -u 10001 -m app && chown -R app:app /app
USER 10001

EXPOSE 8443
ENTRYPOINT ["python", "-u", "app.py"]
