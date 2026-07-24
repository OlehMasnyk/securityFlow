# Shared multi-stage build for the Spring Boot modules.
# docker-compose passes MODULE (e.g. bff-gateway) as a build argument.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY . .
ARG MODULE
RUN mvn -q -B -pl ${MODULE} -am -DskipTests package \
    && cp ${MODULE}/target/*.jar /workspace/app.jar

FROM eclipse-temurin:21-jre
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN useradd --system --uid 1001 spring
USER spring
COPY --from=build /workspace/app.jar app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
