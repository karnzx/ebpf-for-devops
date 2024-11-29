#!/usr/bin/python
from bcc import BPF

program = """
int hello_world(void *ctx) {
    bpf_trace_printk("Hello World! NongKai is here. Enjoy!\\n");
    return 0;
}
"""
try:
    b = BPF(text=program)
    syscall = b.get_syscall_fnname("execve")  # get every event that execute
    b.attach_kprobe(
        event=syscall, fn_name="hello_world"
    )  # attach kprobe function hello_world
    b.trace_print()

except KeyboardInterrupt:
    print("Exiting...")

