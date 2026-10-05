FROM python:3.12-slim-bookworm

# Install native dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    file \
    exiftool \
    binutils \
    imagemagick \
    pngcheck \
    binwalk \
    foremost \
    ruby \
    rubygems \
    steghide \
    outguess \
    poppler-utils \
    sox \
    zbar-tools \
    && gem install zsteg --no-document \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Hardening for ImageMagick
RUN sed -i 's/rights="none" pattern="PS"/rights="none" pattern="*"/g' /etc/ImageMagick-6/policy.xml || true
RUN echo '<policymap><policy domain="delegate" rights="none" pattern="*"/></policymap>' > /etc/ImageMagick-6/policy.xml

WORKDIR /app
COPY backend/pyproject.toml backend/requirements.txt* /app/
RUN pip install --no-cache-dir 'flask==3.0.3' 'gunicorn==22.0.0' 'pillow==10.3.0' 'numpy==1.26.4' 'werkzeug==3.0.3'

COPY backend/stego_triage/ /app/stego_triage/
COPY frontend/ /app/frontend/

# Create non-root user
RUN useradd -m -s /bin/bash stego && \
    mkdir -p /runtime && \
    chown stego:stego /runtime

USER stego

EXPOSE 8766
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=stego_triage.app
ENV FRONTEND_ROOT=/app/frontend
ENV RUNTIME_ROOT=/runtime

CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:8766", "--threads", "2", "stego_triage.app:app"]
