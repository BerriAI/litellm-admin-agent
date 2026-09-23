FROM python:3.12.13-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 OPENAI_AGENTS_DISABLE_TRACING=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY LICENSE agent.py app.py auth.py core.py engine.py web.py connections.py sso.py connect.js doctor.py ./
RUN useradd --uid 10001 --create-home agent && mkdir /var/data && chown agent:agent /var/data
USER agent
ENV STATE_DB=/var/data/events.sqlite3 PORT=10000
EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:10000/readyz', timeout=3)"
CMD ["python", "app.py", "--web"]
