FROM ubuntu:22.04

# Install required dependencies
RUN apt-get update && apt-get install -y \
    bash \
    grep \
    gawk \
    sed \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /opt/incident-response-framework

# Copy the framework files
COPY . .

# Set permissions
RUN chmod -R 750 /opt/incident-response-framework/bin
RUN chmod -R 640 /opt/incident-response-framework/conf
RUN chmod 750 /opt/incident-response-framework/conf /opt/incident-response-framework/conf/sources /opt/incident-response-framework/conf/rules /opt/incident-response-framework/conf/actions

# Set environment variables
ENV IRF_ROOT=/opt/incident-response-framework

# Set the entrypoint
ENTRYPOINT ["/opt/incident-response-framework/bin/irf", "respond"]