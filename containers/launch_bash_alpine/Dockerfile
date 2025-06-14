FROM ubuntu:latest

# Install netcat
RUN apt-get update && apt-get install -y netcat

# Copy the bash script
COPY . .

# Set the script as executable
RUN chmod +x ./netserver.sh

# Expose port 9090
EXPOSE 9090

# Start the netserver
CMD ["./netserver.sh"]