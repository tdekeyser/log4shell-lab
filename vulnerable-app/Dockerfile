FROM openjdk:11-slim
COPY build/libs/vulnerable-app-0.0.1-SNAPSHOT.jar /vulnerable-app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/vulnerable-app.jar"]
