
FROM eclipse-temurin:17-jdk-alpine AS builder

WORKDIR /tmp/app

COPY . /tmp/app
RUN chmod +x gradlew

RUN ./gradlew clean build --stacktrace

FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

COPY --from=builder /tmp/app/build/libs/*.jar /app/app.jar
COPY entrypoint.sh          /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh \
 && apk add --no-cache bash

EXPOSE 8080
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
