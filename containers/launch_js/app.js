const net = require('net');

const server = net.createServer((socket) => {
    socket.on('data', (data) => {
        // Respond with an empty string
        socket.write('');
    });
});

server.listen(9090, () => {
    console.log('Server listening on port 9090');
});