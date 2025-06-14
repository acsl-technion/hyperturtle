import java.io.*;
import java.net.*;

public class HelloWorld {
    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(9090);

            while (true) {
                Socket clientSocket = serverSocket.accept();

                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                out.println(""); // Send an empty string as the response

                clientSocket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}