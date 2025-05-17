# Use JDK image with matching architecture
FROM eclipse-temurin:17-jdk AS builder

WORKDIR /tmp/app
COPY . /tmp/app

# Set gradlew permissions and build
RUN chmod +x gradlew && ./gradlew clean build --stacktrace

# Use matching JRE image for runtime
FROM eclipse-temurin:17-jre

WORKDIR /app

# Copy built jar
COPY --from=builder /tmp/app/build/libs/*.jar /app/app.jar

# Use sh instead of bash for alpine compatibility
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
