FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /work

# Install test deps once (cached layer)
COPY tests/requirements.txt /tmp/req.txt
RUN pip install --no-cache-dir -r /tmp/req.txt

# Source is bind-mounted at runtime so edits are picked up without rebuild.
# But we also copy on build for `docker compose run` ergonomics.
COPY client /work/client
COPY tests  /work/tests
COPY pytest.ini /work/pytest.ini

ENV PYTHONPATH=/work

# clients/ is bind-mounted from the host at runtime.
CMD ["pytest", "-q"]
