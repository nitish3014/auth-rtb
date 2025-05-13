FROM eclipse-temurin:17-jdk-alpine as builder

WORKDIR /tmp/app

COPY . /tmp/app

RUN ./gradlew clean build --stacktrace

FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

COPY --from=builder /tmp/app/build/libs/bb-auth-service-0.0.1-SNAPSHOT.jar /app/app.jar

COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

RUN apk add --no-cache tini bash

EXPOSE 8080

ENTRYPOINT ["/sbin/tini", "--", "/app/entrypoint.sh"]
