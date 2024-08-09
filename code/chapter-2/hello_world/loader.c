#include "bpf_load.h"
#include <stdio.h>

int main(int argc, char **argv) {
  if (load_bpf_file("bpf_program.o") != 0) {  // 获取二进制文件并加载到内核中
    printf("The kernel didn't load the BPF program\n");
    return -1;
  }

  read_trace_pipe();  // 读取通过`trace_printk()`或其他机制输出到跟踪管道的数据

  return 0;
}
