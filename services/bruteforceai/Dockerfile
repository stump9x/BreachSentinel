FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    BRUTEFORCEAI_REPO=/opt/BruteForceAI \
    PYTHONPATH=/app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git xvfb \
    && rm -rf /var/lib/apt/lists/*

ARG BRUTEFORCEAI_REF=main
RUN git clone --depth 1 --branch "${BRUTEFORCEAI_REF}" \
    https://github.com/MorDavid/BruteForceAI.git \
    "${BRUTEFORCEAI_REPO}" \
    && pip install -r "${BRUTEFORCEAI_REPO}/requirements.txt" \
    && pip install playwright \
    && playwright install --with-deps chromium

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt
COPY main.py /app/main.py
COPY bs_multisignal_detector.py /app/bs_multisignal_detector.py
COPY patches/bruteforceai-multisignal.patch /app/patches/bruteforceai-multisignal.patch
COPY tests /app/tests

RUN git -C "${BRUTEFORCEAI_REPO}" apply --check /app/patches/bruteforceai-multisignal.patch \
    && git -C "${BRUTEFORCEAI_REPO}" apply /app/patches/bruteforceai-multisignal.patch

RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
