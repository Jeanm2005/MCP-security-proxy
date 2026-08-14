# Single shared image for all five Watchtower services (proxy, filesrv,
# mailsrv, blue-agent, red-agent).

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vulnerable-server/ ./vulnerable-server/
COPY lab-server-b/ ./lab-server-b/
COPY proxy/ ./proxy/
RUN rm -f proxy/watchtower.db
COPY agents/ ./agents/