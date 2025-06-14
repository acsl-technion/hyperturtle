FROM alpine
WORKDIR /app
RUN addgroup -g 11211 memcache && adduser -D -u 11211 -G memcache memcache
RUN apk add --no-cache util-linux
RUN apk add --no-cache memcached dhcpcd net-tools su-exec

EXPOSE 11211
CMD dhcpcd; ifconfig -a; su-exec memcache memcached -t 1
