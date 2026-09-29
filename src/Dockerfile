FROM alpine:3.24
LABEL image.authors="William Park"
WORKDIR /home/monocle/
COPY pyproject.toml pyproject.toml
COPY main.py main.py
COPY policy.yaml policy.yaml
COPY gateway-policy.yaml gateway-policy.yaml
COPY skills/ skills/
COPY tools/ tools/
COPY uv.lock uv.lock
ENV UV_PYTHON_INSTALL_DIR=/home/monocle/.uv-python
RUN apk add --no-cache python3=3.14.7-r1 uv=0.11.19-r0 && \
    apk upgrade --no-cache libcrypto3 libssl3 &&\
    uv sync --frozen --python /usr/bin/python3 && \
    addgroup -g 1000 monocle &&\
    adduser -D -G monocle -u 1000 monocle -h /home/monocle/ &&\
    chown -R monocle:monocle /home/monocle/
ENV PATH="/home/monocle/.venv/bin:$PATH"
USER 1000
EXPOSE 8002
CMD [ "python", "-m", "main" ]
