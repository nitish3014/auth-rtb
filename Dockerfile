# Use explicit platform in builder stage
FROM --platform=linux/amd64 eclipse-temurin:17-jdk AS builder

WORKDIR /tmp/app
COPY . /tmp/app
RUN chmod +x gradlew && ./gradlew clean build --stacktrace

# Use matching platform in runtime stage
FROM --platform=linux/amd64 eclipse-temurin:17-jre

WORKDIR /app
COPY --from=builder /tmp/app/build/libs/*.jar /app/app.jar
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
