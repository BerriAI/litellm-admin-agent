FROM python:3.12.13-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 OPENAI_AGENTS_DISABLE_TRACING=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent.py app.py auth.py core.py engine.py web.py connections.py admin-operations.json ./
RUN useradd --uid 10001 --create-home agent && mkdir /var/data && chown agent:agent /var/data
USER agent
ENV STATE_DB=/var/data/events.sqlite3 PORT=10000
EXPOSE 10000
CMD ["python", "app.py", "--web"]
