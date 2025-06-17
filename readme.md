# Hyperturtle
This repository contains the source code and evaluation scripts for the USENIX ATC'25 paper "Accelerating Nested Virtualization with HyperTurtle".

## Repository Structure
- Linux Kernel for L0 and L1
- Libbpf for L0 (Required for L0 QEMU)
- L0 QEMU
- Hyperupcall programs and infrastructure
- Evaluation scripts and tools

## System setup
The used `Ubuntu 20.04.6 LTS` as L0 OS and build environment.

## Build Instructions
1. Clone repository with submodules

2. Build and install the [kernel](https://github.com/OriBenZur/hyperturtle-linux/tree/ff0190f81a93bff05ab43ed5218ae7ba558a3b43) in L0.
```
cd hyperturtle-linux
make hyperturtle_defconfig
make -j$(nproc)
sudo make install
sudo make modules_install
```

3. Build and install [libbpf](https://github.com/OriBenZur/hyperturtle-linux/tree/ff0190f81a93bff05ab43ed5218ae7ba558a3b43/tools/lib/bpf).

4. Build [L0 QEMU](https://github.com/OriBenZur/hyperturtle-qemu/tree/da3218d45fb8611d73edc3c0eb5c6b20658c86b2). Ensure it uses the libbpf version you installed.
```
cd hyperturtle-qemu
mkdir build
cd build
../configure --target-list=x86_64-softmmu
make
```

5. Create L1 VM with the kernel + libbpf above.

6. Launch L1 VM with the `launch_virt.sh` script (TODO: add `launch_virt.sh`).

7. (Optional) Install Kata Containers in L1.

8. Build Hyperupcall programs on L1.
In `hyperupcalls/hyperupcall.h`, change the value of `NETDEV_INDEX` such that it'll reference the i'th network device connected to L0 (can see the numbering via `lspci`).

9. Start L2 VM (either via QEMU or Kata Containers). The Dockerfiles for the containers used in the paper are available [here](containers).
For optimal performance, pin L1-vCPUs to L0-pCPUs and pin L2-vCPUs to L1-vCPUs.

To start a Kata Container with a directly attached virtual device, you need to:

```
# Override the driver of a virtio-nic. You might need to install driverctl. Replace <pci-id> - example: 0000:01:00.0
sudo apt install driverctl
sudo driverctl set-override <pci-id> vfio-pci

# Run the container without docker network, but attach a device. You might need to add --cap-add=NET_ADMIN
docker run --runtime io.containerd.kata.v2 --device /dev/vfio/<device-index> --network=none <image-name>

# You might need to acquire an IP address from inside the container. Assuming the name of the container is "hyperturtle-test"
docker exec hyperturtle-test dhclient eth0
```

## Evaluation
For the network benchmarks, a second identical machine is connected via 100 gigabit ethernet back-to-back as described in the paper.
To run the memcached benchmarks as an example.
TODO: fill evaluation

1. Clone repository to second host
```sh

```

2. Install mutilate
```sh

```

3. Configure benchmarking scripts


4. Run benchmark
```sh
python3 do_all_bench.py
python3 get_memcached_data.py
```

The mutilate results will be stored in `results/memcached`. The plots are stored in `$CWD`.

## Citation
When referring to this repository, please cite our publication.

```bibtex

```

