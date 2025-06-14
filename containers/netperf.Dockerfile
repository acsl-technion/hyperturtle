FROM alectolytic/netperf
RUN apk add --no-cache dhclient net-tools util-linux
# RUN echo "1af4 1041" > /sys/bus/pci/drivers/virtio-pci/new_id
CMD dhclient eth0; ifconfig -a; /usr/bin/netserver -D
# CMD ["/usr/bin/netserver", "-D"]
