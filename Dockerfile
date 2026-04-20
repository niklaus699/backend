FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# Force Django to use production settings for collectstatic
ENV DJANGO_SETTINGS_MODULE=config.settings.production

WORKDIR /app

# 1. Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

# 2. Create the user ONCE
RUN useradd -m -u 1000 appuser

# 3. Copy requirements and install
COPY requirements/ requirements/
RUN pip install --no-cache-dir -r requirements/production.txt

# 4. Copy the code (needed for collectstatic to find your files)
# We do this as root first to run collectstatic
COPY . .


# 5. Prepare Static Files
# We use a dummy Secret Key so Django doesn't complain during the build
# 5. Prepare Static Files
RUN SECRET_KEY=build-dummy \
    DJANGO_SECRET_KEY=build-dummy \
    DATABASE_URL=postgres://user:pass@localhost:5432/db \
    python manage.py collectstatic --noinput

# 6. Fix permissions and switch user
RUN chown -R appuser:appuser /app
USER appuser


EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health/ || exit 1

# 7. Run migrations and start server
CMD ["sh", "-c", "python manage.py migrate && daphne -b 0.0.0.0 -p 8000 config.asgi:application"]