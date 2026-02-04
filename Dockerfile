FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip \
  && python -m pip install --no-cache-dir -r /app/requirements.txt

COPY scratchchain /app/scratchchain
COPY ops /app/ops

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/app/ops/docker/entrypoint.sh"]
