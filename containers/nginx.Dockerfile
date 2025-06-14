FROM ubuntu/nginx:latest

RUN apt update
RUN apt install -y dhcpcd

CMD ["bash", "-c", "ip link set eth0 up && dhcpcd && nginx -g daemon off;"]
