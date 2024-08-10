from bcc import BPF, USDT

bpf_source = """
#include <uapi/linux/ptrace.h>
int trace_binary_exec(struct pt_regs *ctx) {
  u64 pid = bpf_get_current_pid_tgid();
  bpf_trace_printk("New hello_usdt process running with PID: %d\\n", pid);
}
"""

usdt = USDT(path = "./hello_usdt")  # 创建一个USDT对象。USDT不是BPF的一部分
usdt.enable_probe(probe = "probe-main", fn_name = "trace_binary_exec")  # 将BPF函数附加到应用探针上用来跟踪程序执行
bpf = BPF(text = bpf_source, usdt_contexts = [usdt])  # 使用创建的跟踪点定义来初始化BPF环境，通知BCC生成代码将BPF程序与二进制文件中定义的探针连接起来
bpf.trace_print()
