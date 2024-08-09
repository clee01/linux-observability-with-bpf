# -*- coding: utf-8 -*-

from bcc import BPF

bpf_source = """
#include <uapi/linux/ptrace.h>

int do_sys_execve(struct pt_regs *ctx) {
  char comm[16];  // 内核对程序命令名有16个字符的限制，所以这儿可以定义为固定长度的数组
  bpf_get_current_comm(&comm, sizeof(comm));
  bpf_trace_printk("executing program: %s\\n", comm);
  return 0;
}
"""

bpf = BPF(text=bpf_source)  # 加载BPF程序到内核中
execve_function = bpf.get_syscall_fnname("execve")  # 将BPF程序与execve系统调用关联
bpf.attach_kprobe(event=execve_function, fn_name="do_sys_execve")  # 附加函数为attach_kprobe
bpf.trace_print()  # 输出跟踪日志
