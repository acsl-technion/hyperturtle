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

2. Build and install L0 kernel

3. Build and install libbpf

4. Build L0 QEMU 

5. Create L1 VM with the above kernel.

6. Launch L1 VM with the `launch_virt.sh` script

7. (Optional) Install Kata Containers in L1

8. Build Hyperupcall programs on L1

9. Start L2 VM (either via QEMU or Kata Containers).

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

