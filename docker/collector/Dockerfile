FROM ubuntu:22.04 AS builder

# Install Python dependencies in a separate stage
WORKDIR /build
COPY requirements.txt .
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && pip3 install --prefix=/build -r requirements.txt \
    && rm -rf /var/lib/apt/lists/*

FROM ubuntu:22.04

# Create non-root user
RUN groupadd -r irf && useradd -r -g irf -d /opt/incident-response-framework irf

# Install only required dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    grep \
    gawk \
    sed \
    inotify-tools \
    python3 \
    python3-minimal \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /opt/incident-response-framework

# Copy specific directories needed
COPY --from=builder /build/lib/python*/site-packages /usr/local/lib/python3.10/dist-packages/
COPY bin /opt/incident-response-framework/bin/
COPY lib /opt/incident-response-framework/lib/
COPY conf /opt/incident-response-framework/conf/

# Create necessary directories with proper permissions
RUN mkdir -p logs evidence/incidents evidence/archives \
    && chown -R irf:irf /opt/incident-response-framework

# Set proper permissions
RUN chmod -R 750 bin \
    && chmod -R 640 conf/* \
    && chmod 750 conf conf/sources conf/rules conf/actions

# Set environment variables
ENV IRF_ROOT=/opt/incident-response-framework

# Switch to non-root user
USER irf

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD test -f /opt/incident-response-framework/logs/irf.log || exit 1

# Set the entrypoint
ENTRYPOINT ["/opt/incident-response-framework/bin/irf", "collect"]