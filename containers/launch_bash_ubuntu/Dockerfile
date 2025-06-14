FROM alpine:latest

# Install netcat
RUN apk update && apk add --no-cache netcat-openbsd

# Copy the bash script
COPY . .

# Set the script as executable
RUN chmod +x ./netserver.sh

# Expose port 9090
EXPOSE 9090

# Start the netserver
CMD ["./netserver.sh"]