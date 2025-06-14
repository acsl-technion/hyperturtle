FROM redis:latest

RUN apt update && apt install -y iproute2 net-tools isc-dhcp-client

CMD ["redis-server"]