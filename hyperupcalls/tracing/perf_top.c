#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <stdlib.h>

#define CPU_FREQ 2100000000
#define DEFAULT_FREQ 1000

unsigned int get_sample_time_from_frequency(unsigned int freq) {
    return CPU_FREQ / freq;
}

int set_perf_event(unsigned long sample_freq) {
    int fd;
    struct perf_event_attr attr = {0};

    attr.type = PERF_TYPE_SOFTWARE;
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.size = sizeof(attr);
    attr.freq = 1;
    attr.sample_freq = sample_freq;
    // attr.sample_period = sample_period;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.disabled = 1;
    attr.inherit = 1;
    attr.mmap = 1;
    attr.comm = 1;
    attr.task = 1;
    attr.sample_id_all = 1;
    attr.exclude_host = 1;
    attr.mmap2 = 1;
    
    // perf_event_open({type=PERF_TYPE_HARDWARE, size=PERF_ATTR_SIZE_VER5, config=PERF_COUNT_HW_CPU_CYCLES, sample_freq=4000, sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_TID|PERF_SAMPLE_TIME|PERF_SAMPLE_CPU|PERF_SAMPLE_PERIOD, read_format=0, disabled=1, inherit=1, pinned=0, exclusive=0, exclusive_user=0, exclude_kernel=0, exclude_hv=0, exclude_idle=0, mmap=1, comm=1, freq=1, inherit_stat=0, enable_on_exec=0, task=1, watermark=0, precise_ip=0 /* arbitrary skid */, mmap_data=0, sample_id_all=1, exclude_host=1, exclude_guest=0, exclude_callchain_kernel=0, exclude_callchain_user=0, mmap2=1, comm_exec=1, use_clockid=0, context_switch=0, write_backward=0, namespaces=0, wakeup_events=0, config1=0, config2=0, sample_regs_user=0, sample_regs_intr=0, aux_watermark=0, sample_max_stack=0}, -1, 5, -1, PERF_FLAG_FD_CLOEXEC) = 4
    fd = syscall(SYS_perf_event_open, &attr, -1, 5, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        perror("Failed to open perf event");
        return -1;
    }
    return fd;
}


int main(int argc, char *argv[]) {
    int r;
    int perf_fd;
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    unsigned int frequency = DEFAULT_FREQ;
    unsigned long sample_period = get_sample_time_from_frequency(frequency);

    if (argc > 1 && strcmp(argv[1], "-F") == 0 && argc > 2) {
        frequency = strtoui(argv[2], NULL, 10);
        sample_period = get_sample_time_from_frequency(frequency);
    }
    printf("Setting sample period to %lu (frequency is %u)\n", sample_period, frequency);

    obj = bpf_object__open_file("perf_top.bpf.o", NULL);
    if (!obj) {
        perror("Failed to open BPF object");
        return -1;
    }

    r = bpf_object__load(obj);
    if (r < 0) {
        perror("Failed to load BPF object");
        return r;
    }

    prog = bpf_object__find_program_by_name(obj, "do_perf_event");
    if (!prog) {
        perror("Failed to find BPF program");
        return -1;
    }


    perf_fd = set_perf_event(frequency);
    if (perf_fd < 0) {
        perror("Failed to set perf event");
        return -1;
    }

    struct bpf_link *link = bpf_program__attach_perf_event(prog, perf_fd);
    if (link == NULL) {
        perror("Failed to attach perf event");
        return -1;
    }
    if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
        perror("Failed to enable perf event");
        return -1;
    }
    printf("Press Ctrl+C to stop\n");
    while (1) {
        sleep(1);
    }
}