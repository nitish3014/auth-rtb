# Stage 1: Build
FROM eclipse-temurin:17-jdk AS builder
WORKDIR /tmp/app
COPY . /tmp/app
RUN chmod +x gradlew
RUN ./gradlew clean build --stacktrace

# Stage 2: Runtime
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=builder /tmp/app/build/libs/*.jar /app/app.jar
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh && apt-get update && apt-get install -y bash && rm -rf /var/lib/apt/lists/*
EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
