# Use a base image with Java installed
FROM eclipse-temurin:21

# Set the working directory inside the container
WORKDIR /app

# Copy the Java source code to the container
COPY HelloWorld.java .

# Compile the Java source code
RUN javac HelloWorld.java

# Run the Java program
CMD ["java", "HelloWorld"]