FROM maven:3-openjdk-17-slim

COPY pom.xml ./
COPY src ./src

RUN mvn clean install

ENTRYPOINT ["mvn", "exec:java", "-Dexec.mainClass=org.compare.Main"]
