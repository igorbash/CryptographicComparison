FROM maven:3-openjdk-17-slim AS build

WORKDIR /app
COPY pom.xml ./
COPY src ./src

RUN mvn -f pom.xml clean package

RUN ls target
FROM openjdk:17-slim

COPY --from=build /app/target/CryptographicComparison-1.0-SNAPSHOT.jar CryptographicComparison.jar

ENTRYPOINT ["java","-jar","CryptographicComparison.jar"]