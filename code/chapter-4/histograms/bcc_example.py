import sys
import signal
from time import sleep

from bcc import BPF


def signal_ignore(signal, frame):
    print()


bpf_source = """
#include <uapi/linux/ptrace.h>

BPF_HASH(cache, u64, u64);  // 使用BCL宏创建BPF哈希映射
BPF_HISTOGRAM(histogram);  // 创建BPF直方图映射

int trace_bpf_prog_load_start(void *ctx) {
  u64 pid = bpf_get_current_pid_tgid();
  u64 start_time_ns = bpf_ktime_get_ns();
  cache.update(&pid, &start_time_ns);
  return 0;
}
"""

bpf_source += """
int trace_bpf_prog_load_return(void *ctx) {
  u64 *start_time_ns, delta;
  u64 pid = bpf_get_current_pid_tgid();
  start_time_ns = cache.lookup(&pid);
  if (start_time_ns == 0)
    return 0;

  delta = bpf_ktime_get_ns() - *start_time_ns;
  histogram.increment(bpf_log2l(delta));  // 使用内置函数bpf_log2l为差值生成桶标识符
  return 0;
}
"""

bpf = BPF(text=bpf_source)
bpf.attach_kprobe(event="bpf_prog_load", fn_name="trace_bpf_prog_load_start")
bpf.attach_kretprobe(event="bpf_prog_load",
                     fn_name="trace_bpf_prog_load_return")


try:
    sleep(300)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)

bpf["histogram"].print_log2_hist("msecs")  # 在终端中打印包含跟踪事件分布的直方图映射
