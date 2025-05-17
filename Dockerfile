# Stage 1: Builder with Gradle cache
FROM --platform=linux/amd64 eclipse-temurin:17-jdk-alpine as builder

WORKDIR /tmp/app

# Cache Gradle dependencies
COPY gradle gradle
COPY gradlew .
COPY build.gradle .
COPY settings.gradle .
RUN ./gradlew dependencies --no-daemon

# Build application
COPY src src
RUN ./gradlew clean build -x test --no-daemon --stacktrace

# Stage 2: Slim runtime image
FROM --platform=linux/arm64 eclipse-temurin:17-jre-alpine

WORKDIR /app

# Copy built jar
COPY --from=builder /tmp/app/build/libs/*.jar /app/app.jar

# Copy entrypoint
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Install tini for proper signal handling
RUN apk add --no-cache tini bash

EXPOSE 8080
ENTRYPOINT ["/sbin/tini", "--", "/app/entrypoint.sh"]
