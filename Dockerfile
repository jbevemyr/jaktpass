FROM erlang:26-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends yaws make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

RUN mkdir -p /var/log/yaws /app/priv/data \
    && make clean \
    && make compile

ENV JAKTPASS_DATA_DIR=/app/priv/data \
    JAKTPASS_ADMIN_USER=admin \
    JAKTPASS_ADMIN_PASS=admin \
    JAKTPASS_COOKIE_SECURE=false

EXPOSE 8080

CMD ["yaws", "-c", "/app/yaws.conf", "--erlarg", "-noshell -noinput"]
