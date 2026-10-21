# Explicit local-only build; independent container OS qualification.
FROM python:3.12.15-slim-trixie@sha256:2259debdc6af85626058a15a7bf44ad6a68b8c98c9ae82a02cf5cdb92f096d47
ARG WHEEL_SHA256
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY wheels/ /build/wheels/
COPY requirements.txt osint_workbench-0.1.0.dev1-py3-none-any.whl /build/
RUN python -c 'import hashlib,os; ok=hashlib.sha256(open("/build/osint_workbench-0.1.0.dev1-py3-none-any.whl","rb").read()).hexdigest()==os.environ["WHEEL_SHA256"]; raise SystemExit(0 if ok else "PROFILE_WHEEL_DIGEST_MISMATCH")' \
 && python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-index --find-links=/build/wheels --require-hashes -r /build/requirements.txt \
 && /opt/venv/bin/pip install --no-index --no-deps /build/*-py3-none-any.whl \
 && /opt/venv/bin/pip check \
 && rm -rf /build
COPY entrypoint.py bootstrap.py acceptance.py /opt/profile/
ENV PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin
USER 10003:10100
ENTRYPOINT ["/opt/venv/bin/python", "-I", "/opt/profile/entrypoint.py"]
