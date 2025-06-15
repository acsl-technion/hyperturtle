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

3. Build and install [libbpf](https://github.com/OriBenZur/hyperturtle-libbpf/tree/950a896dc34e4bd97f971af0c4a7783dc51049a2).

4. Build [L0 QEMU](https://github.com/OriBenZur/hyperturtle-qemu/tree/da3218d45fb8611d73edc3c0eb5c6b20658c86b2). Ensure it uses the libbpf version you installed.
```
cd hyperturtle-qemu
mkdir build
cd build
../configure --target-list=x86_64-softmmu
make
```

6. Create L1 VM with the above kernel.

7. Launch L1 VM with the `launch_virt.sh` script (TODO: add `launch_virt.sh`).

8. (Optional) Install Kata Containers in L1.

9. Build Hyperupcall programs on L1.
In `hyperupcalls/hyperupcall.h`, change the value of `NETDEV_INDEX` such that it'll reference the i'th network device connected to L0 (can see the numbering via `lspci`).

11. Start L2 VM (either via QEMU or Kata Containers). The Dockerfiles for the containers used in the paper are available [here](containers).
For optimal performance, pin L1-vCPUs to L0-pCPUs and pin L2-vCPUs to L1-vCPUs.
TODO: add guide to start a Kata Container with a directly assigned virtual device.

## Evaluation
For the network benchmarks, a second identical machine is connected via 100 gigabit ethernet back-to-back as described in the paper.
To run the memcached benchmarks as an example.

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

## License
The hyperupcall programs and scripts are licensed under TODO. All submodules are licensed individually.

## Citation
When referring to this repository, please cite our publication.

```bibtex

```

