# AndroGuard on Debian: web app + CLI, apktool + jadx + bundletool + FlowDroid, XGBoost + fine-tuned CodeBERT,
# PDF reports through WeasyPrint. Needs data/models/codebert-lvdandro (python -m app.modules.ml.codebert) to build.
# Alone (SQLite):    docker run -d -p 8000:8000 -v androguard-db:/srv/db --name androguard <image>
# With PostgreSQL:   docker compose up --build   (see docker-compose.yml)
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends openjdk-17-jre-headless curl unzip \
        libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

ARG APKTOOL=3.0.3
ARG JADX=1.5.6
ARG BUNDLETOOL=1.18.3
RUN mkdir -p /opt/apktool /opt/jadx \
    && curl -fsSL -o /opt/apktool/apktool.jar https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL}/apktool_${APKTOOL}.jar \
    && printf '#!/bin/sh\nexec java -jar /opt/apktool/apktool.jar "$@"\n' > /usr/local/bin/apktool && chmod +x /usr/local/bin/apktool \
    && curl -fsSL -o /tmp/jadx.zip https://github.com/skylot/jadx/releases/download/v${JADX}/jadx-${JADX}.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx && rm /tmp/jadx.zip && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && curl -fsSL -o /opt/bundletool.jar https://github.com/google/bundletool/releases/download/${BUNDLETOOL}/bundletool-all-${BUNDLETOOL}.jar
ARG FLOWDROID=2.13
RUN mkdir -p /opt/flowdroid/platforms/android-33 \
    && curl -fsSL -o /opt/flowdroid/soot-infoflow-cmd.jar https://github.com/secure-software-engineering/FlowDroid/releases/download/v${FLOWDROID}/soot-infoflow-cmd-${FLOWDROID}.0-jar-with-dependencies.jar \
    && curl -fsSL -o /opt/flowdroid/SourcesAndSinks.txt https://raw.githubusercontent.com/secure-software-engineering/FlowDroid/v${FLOWDROID}/soot-infoflow-android/SourcesAndSinks.txt \
    && curl -fsSL -o /opt/flowdroid/platforms/android-33/android.jar https://raw.githubusercontent.com/Sable/android-platforms/master/android-33/android.jar
ENV BUNDLETOOL_JAR=/opt/bundletool.jar FLOWDROID_DIR=/opt/flowdroid PYTHONUNBUFFERED=1

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# CPU-only torch: the default wheel brings ~3 GB of CUDA libraries that a scanner never uses
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.14.1 \
    && pip install --no-cache-dir transformers==5.18.0
COPY data/models/codebert-lvdandro ./data/models/codebert-lvdandro
COPY app ./app
RUN useradd --create-home androguard && mkdir /srv/db && chown androguard /srv/db
ENV DATABASE_URL=sqlite:////srv/db/androguard.db
USER androguard
EXPOSE 8000
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]
