#!/usr/bin/python
from bcc import BPF
from time import sleep

# Everytime that user run command it will count number up along with userID
# There could have some process running in background that make count increase with id 0

program = """
BPF_HASH(clones);

int hello_world(void *ctx) {
   u64 uid;
   u64 counter = 0;
   u64 *p;

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = clones.lookup(&uid);
   if (p != 0) {
      counter = *p;
   }

   counter++;
   clones.update(&uid, &counter);

   return 0;
}
"""

b = BPF(text=program)
clone = b.get_syscall_fnname("clone")
b.attach_kprobe(event=clone, fn_name="hello_world")

while True:
    sleep(2)
    s = ""
    if len(b["clones"].items()):
        for k, v in b["clones"].items():
            s += "ID {}: {}\t".format(k.value, v.value)
        print(s)
    else:
        print("No entries yet")
