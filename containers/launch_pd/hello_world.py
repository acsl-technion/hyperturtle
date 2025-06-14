import pandas as pd
import socket

def main():
    # Create a socket object
    num = pd.DataFrame()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific address and port
    server_socket.bind(('0.0.0.0', 9090))

    # Listen for incoming connections
    server_socket.listen(1)

    while True:
        # Accept a connection from a client
        client_socket, client_address = server_socket.accept()

        # Receive data from the client
        data = client_socket.recv(1024).decode('utf-8')

        # Send an empty string as the response
        response = ''
        client_socket.sendall(response.encode('utf-8'))

        # Close the connection
        client_socket.close()

if __name__ == '__main__':
    main()