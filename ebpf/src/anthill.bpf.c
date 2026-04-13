#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("kprobe/sys_execve")
int BPF_KPROBE(sys_execve, const char *filename) {
    struct event e = {};
    struct task_struct *task;

    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    
    // Get parent PID
    task = (struct task_struct *)bpf_get_current_task();
    e.ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    // Get UID
    e.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), filename);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
