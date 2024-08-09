from bcc import BPF

bpf_source = """
#include <uapi/linux/ptrace.h>

int ret_sys_execve(struct pt_regs *ctx) {
  int return_value;
  char comm[16];  // 内核对程序命令名有16个字符的限制，所以这儿可以定义为固定长度的数组
  bpf_get_current_comm(&comm, sizeof(comm));
  return_value = PT_REGS_RC(ctx);  // 宏PT_REGS_RC用来从特定上下文中读取BPF寄存器的返回值

  bpf_trace_printk("program: %s, return: %d\\n", comm, return_value);
  return 0;
}
"""

bpf = BPF(text=bpf_source)  # 加载BPF程序到内核中
execve_function = bpf.get_syscall_fnname("execve")  # 将BPF程序与execve系统调用关联
bpf.attach_kretprobe(event=execve_function, fn_name="ret_sys_execve")  # 附加函数为attach_kretprobe
bpf.trace_print()  # 输出跟踪日志
