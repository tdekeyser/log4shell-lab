FROM openjdk:11-slim
COPY build/libs/victim-0.0.1-SNAPSHOT.jar /victim.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/victim.jar"]
