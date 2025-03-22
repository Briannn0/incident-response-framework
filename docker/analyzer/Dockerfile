FROM ubuntu:22.04

# Install required dependencies
RUN apt-get update && apt-get install -y \
    bash \
    grep \
    gawk \
    sed \
    inotify-tools \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /opt/incident-response-framework

# Copy the framework files
COPY . .

# Set permissions
RUN chmod -R 750 /opt/incident-response-framework/bin
RUN chmod -R 640 /opt/incident-response-framework/conf
RUN chmod 750 /opt/incident-response-framework/conf /opt/incident-response-framework/conf/sources /opt/incident-response-framework/conf/rules /opt/incident-response-framework/conf/actions

# Create necessary directories
RUN mkdir -p /opt/incident-response-framework/logs /opt/incident-response-framework/evidence/incidents /opt/incident-response-framework/evidence/archives

# Set environment variables
ENV IRF_ROOT=/opt/incident-response-framework

# Set the entrypoint
ENTRYPOINT ["/opt/incident-response-framework/bin/irf", "collect"]