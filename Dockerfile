# The Teeckbox agent as a container image: a single self-contained file on a minimal base without a shell, run as a non-root user.
#   docker run --rm -v teeckbox-agent:/data -v ./agent.yaml:/config/agent.yaml:ro ghcr.io/teeckbox/teeckbox-agent enroll --url https://… --code tbe_…
#   docker run -d --restart unless-stopped -v teeckbox-agent:/data -v ./agent.yaml:/config/agent.yaml:ro ghcr.io/teeckbox/teeckbox-agent
ARG DOTNET_SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0
ARG RUNTIME_IMAGE=mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-chiseled

FROM --platform=$BUILDPLATFORM ${DOTNET_SDK_IMAGE} AS build
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY src/ src/
RUN case "$TARGETARCH" in amd64) rid=linux-x64 ;; arm64) rid=linux-arm64 ;; *) echo "Unsupported architecture $TARGETARCH" >&2; exit 1 ;; esac \
 && dotnet publish src/Teeckbox.Agent -c Release -r "$rid" --self-contained \
      -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:DebugType=None \
      -p:InformationalVersion="$VERSION" -p:ContinuousIntegrationBuild=true -o /out \
 && mkdir -p /data && chown 1654:1654 /data

FROM ${RUNTIME_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/Teeckbox/teeckbox-agent" \
      org.opencontainers.image.description="Teeckbox on-premises agent" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/teeckbox-agent /usr/local/bin/teeckbox-agent
COPY --from=build --chown=1654:1654 /data /data
# The keys and the state are in /data (mount a volume); the configuration is read from /config/agent.yaml (mount the file).
ENV TEECKBOX_AGENT_DATA_FOLDER=/data \
    TEECKBOX_AGENT_CONFIG=/config/agent.yaml
VOLUME ["/data"]
USER 1654:1654
ENTRYPOINT ["/usr/local/bin/teeckbox-agent"]
CMD ["run"]
