# Single shared image for all three Watchtower services (proxy, filesrv,
# mailsrv). They have identical Python dependencies, so one image built
# once and reused with a different CMD per service is simpler to maintain
# than three near-identical Dockerfiles, and keeps the dependency layer
# cached across all three in Compose.

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vulnerable-server/ ./vulnerable-server/
COPY lab-server-b/ ./lab-server-b/
COPY proxy/ ./proxy/