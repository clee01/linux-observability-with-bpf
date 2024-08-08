#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))  // 告知BPF虚拟机何时运行此程序

static int (*bpf_trace_printk)(const char *fmt, int fmt_size,
                               ...) = (void *)BPF_FUNC_trace_printk;

SEC("tracepoint/syscalls/sys_enter_execve")  // 该跟踪点是内核二进制代码中的静态标记
int bpf_prog(void *ctx) {
  char msg[] = "Hello, BPF World!";
  bpf_trace_printk(msg, sizeof(msg));
  return 0;
}

// Linux内核采用GPL许可证，
// 所以它只能加载GPL许可证程序。
// 如果将程序设置为其他许可证，
// 内核将拒绝加载该程序。
char _license[] SEC("license") = "GPL";
