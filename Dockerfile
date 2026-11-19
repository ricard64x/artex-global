# ARTEX Global - Fly.io
# Uses precompiled image

FROM ghcr.io/jiwoochris/artex-global:v0.3.15-global.1

ENV ARTEX_LANG=es

WORKDIR /app

EXPOSE 8787

# Preserve original image entrypoint
CMD ["-addr", ":8787", "-proxy", "127.0.0.1:8788"]
