from bcc import BPF

bpf_source = """
int trace_bpf_prog_load(void ctx) {  // 声明定义BPF程序的函数
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));

  bpf_trace_printk("%s is loading a BPF program", comm);
  return 0;
}
"""

bpf = BPF(text = bpf_source)
bpf.attach_tracepoint(tp = "bpf:bpf_prog_load", fn_name = "trace_bpf_prog_load")  # 附加到跟踪点上
bpf.trace_print()
