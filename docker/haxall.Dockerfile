FROM alpine:3.20 AS fetch
ARG HAXALL_VERSION=4.0.6
RUN apk add --no-cache curl unzip \
    && curl -fsSL -o /tmp/haxall.zip "https://github.com/haxall/haxall/releases/download/v${HAXALL_VERSION}/haxall-${HAXALL_VERSION}.zip" \
    && unzip -q /tmp/haxall.zip -d /tmp \
    && mv "/tmp/haxall-${HAXALL_VERSION}" /haxall

FROM eclipse-temurin:21-jre
WORKDIR /haxall
COPY --from=fetch /haxall/ /haxall/
RUN chmod +x /haxall/bin/*
