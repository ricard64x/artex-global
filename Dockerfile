# ARTEX Global - Fly.io deployment
# Use the upstream prebuilt image; no dist/<arch>/artex artifact is needed.
# Upstream source: https://github.com/jiwoochris/artex-global
FROM ghcr.io/jiwoochris/artex-global:v0.3.15-global.1

ENV ARTEX_LANG=es
WORKDIR /app
EXPOSE 8787

# Preserve the upstream ENTRYPOINT (/app/start.sh).
# Bind the web UI publicly behind Fly's HTTPS proxy.
# Keep the traffic recording proxy on loopback (not publicly exposed).
CMD ["-addr", ":8787", "-proxy", "127.0.0.1:8788"]
