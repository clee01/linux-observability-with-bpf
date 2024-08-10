#!/usr/bin/python

import errno
import signal
import sys
from time import sleep

from bcc import BPF, PerfSWConfig, PerfType


def signal_ignore(signal, frame):
    print()


bpf_source = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

struct trace_t {  // 初始化一个分析器结构体，用于保存分析器接收的每个栈帧的引用标识符
  int stack_id;
};

BPF_HASH(cache, struct trace_t);  // 初始化一个BPF哈希映射，使用该映射聚合相同栈帧出现的频率
BPF_STACK_TRACE(traces, 10000);  // 初始化BPF栈跟踪映射
"""

bpf_source += """
int collect_stack_traces(struct bpf_perf_event_data *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  if (pid != PROGRAM_PID)  // 验证当前BPF上下文中程序进程ID是Go程序的进程ID
    return 0;

  struct trace_t trace = {  // 创建trace来聚合程序栈的使用情况。使用标志BPF_F_USER_STACK设置要获得用户空间程序的栈ID，这里将忽略内核中发生的调用
    .stack_id = traces.get_stackid(&ctx->regs, BPF_F_USER_STACK)
  };

  cache.increment(trace);
  return 0;
}
"""

program_pid = int(sys.argv[1])
bpf_source = bpf_source.replace('PROGRAM_PID', str(program_pid))  # 将BPF程序中的字符PROGRAM_ID替换为提供的分析器的参数

bpf = BPF(text=bpf_source)
bpf.attach_perf_event(ev_type=PerfType.SOFTWARE,
                      ev_config=PerfSWConfig.CPU_CLOCK,
                      fn_name='collect_stack_traces',
                      sample_period=1)  # 将BPF程序附加到所有软件Perf事件上，忽略任何其他事件（例如，硬件事件）。同时，配置BPF程序使用CPU时钟作为时间源，以便测量执行时间

exiting = 0
try:
    sleep(300)
except KeyboardInterrupt:
    exiting = 1
    signal.signal(signal.SIGINT, signal_ignore)

for trace, acc in sorted(bpf['cache'].items(), key=lambda cache: cache[1].value):
    line = []
    if trace.stack_id < 0 and trace.stack_id == -errno.EFAULT:  # 验证获得的栈标识符是否有效，如果无效，将在火焰图中使用一个占位符表示
        line = ['Unknown stack']
    else:
        stack_trace = list(bpf['traces'].walk(trace.stack_id))  # TODO(clee01): 运行失败
        for stack_address in reversed(stack_trace):  # 逆序遍历栈跟踪映射的所有条目
            function_name = bpf.sym(stack_address, program_pid).decode('utf-8')  # BCC的帮助函数sym将栈帧的内存地址转换为源代码中的函数名
            if function_name == '[unknown]':
                continue
            line.extend([function_name])

    if len(line) < 1:
        continue
    frame = ";".join(line)  # 使用分号格式化分隔栈跟踪行。这个格式是后面火焰图脚本识别的格式
    sys.stdout.write("%s %d\n" % (frame, acc.value))
    if exiting:
        exit()
