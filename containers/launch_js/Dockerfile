# Use a Node.js base image
FROM node:22

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Install dependencies
# RUN npm install

# Copy the rest of the application code to the working directory
COPY . .

# Expose a port (if needed)
EXPOSE 3000

# Define the command to run the application
CMD [ "node", "app.js" ]