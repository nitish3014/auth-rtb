FROM eclipse-temurin:17-jdk as builder

WORKDIR /tmp/app

COPY . /tmp/app
RUN chmod +x gradlew

RUN ./gradlew clean build -x test --stacktrace

FROM eclipse-temurin:17-jre

WORKDIR /app

COPY --from=builder /tmp/app/build/libs/*.jar /app/app.jar

COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

RUN apt-get update && apt-get install -y tini bash && \
    ln -sf /usr/bin/tini /sbin/tini && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
    
EXPOSE 8080

ENTRYPOINT ["/sbin/tini", "--", "/app/entrypoint.sh"]
