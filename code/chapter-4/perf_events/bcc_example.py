from bcc import BPF

bpf_source = """
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);  // 定义一个Perf事件映射

// int do_sys_execve(struct pt_regs *ctx, void filename, void argv, void envp) {
int do_sys_execve(struct pt_regs *ctx, char *filename, char **argv, char **envp) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));

  events.perf_submit(ctx, &comm, sizeof(comm));  // 更新Perf事件映射
  return 0;
}
"""

bpf = BPF(text = bpf_source)
execve_function = bpf.get_syscall_fnname("execve")
bpf.attach_kprobe(event = execve_function, fn_name = "do_sys_execve")

from collections import Counter
aggregates = Counter()  # 声明计数器来保存程序消息

def aggregate_programs(cpu, data, size):
  comm = bpf["events"].event(data)  # TODO(clee01): comm is unhashable type
  aggregates[comm] += 1  # 每当收到一个相同程序名的事件，程序计数器的值会增加

bpf["events"].open_perf_buffer(aggregate_programs)  # 每当Perf事件映射接收到一个事件时，通知BCC需要执行aggregate_programs函数
while True:
    try:
      bpf.perf_buffer_poll()  # BCC一直拉取事件直到Python程序被中断
    except KeyboardInterrupt:
      break

for (comm, times) in aggregates.most_common(): 
  print("Program {} executed {} times".format(comm, times))
