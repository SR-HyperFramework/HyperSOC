FROM python:3.12-slim AS runtime

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .
COPY frontend/ /frontend/
COPY integrations/wazuh /integrations/wazuh

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM runtime AS test

COPY backend/requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY benchmarks/ /benchmarks/
COPY integrations/ /integrations/
