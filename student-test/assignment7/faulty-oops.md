# Linux kernel space crash message analysis

Example of a message I got when using the faulty driver:

```
# echo "Hello" >> /dev/faulty 
Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
Mem abort info:
  ESR = 0x0000000096000045
  EC = 0x25: DABT (current EL), IL = 32 bits
  SET = 0, FnV = 0
  EA = 0, S1PTW = 0
  FSC = 0x05: level 1 translation fault
Data abort info:
  ISV = 0, ISS = 0x00000045
  CM = 0, WnR = 1
user pgtable: 4k pages, 39-bit VAs, pgdp=0000000041b59000
[0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
Internal error: Oops: 0000000096000045 [#1] SMP
Modules linked in: faulty(O) hello(O)
CPU: 0 PID: 107 Comm: sh Tainted: G           O       6.1.44 #1
Hardware name: linux,dummy-virt (DT)
pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : faulty_write+0x10/0x20 [faulty]
lr : vfs_write+0xc8/0x390
sp : ffffffc008dd3d20
x29: ffffffc008dd3d80 x28: ffffff8001b9cf80 x27: 0000000000000000
x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
x23: 0000000000000006 x22: 0000000000000006 x21: ffffffc008dd3dc0
x20: 000000556f3b9ac0 x19: ffffff8001bc6800 x18: 0000000000000000
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
x5 : 0000000000000001 x4 : ffffffc000785000 x3 : ffffffc008dd3dc0
x2 : 0000000000000006 x1 : 0000000000000000 x0 : 0000000000000000
Call trace:
 faulty_write+0x10/0x20 [faulty]
 ksys_write+0x74/0x110
 __arm64_sys_write+0x1c/0x30
 invoke_syscall+0x54/0x130
 el0_svc_common.constprop.0+0x44/0xf0
 do_el0_svc+0x2c/0xc0
 el0_svc+0x2c/0x90
 el0t_64_sync_handler+0xf4/0x120
 el0t_64_sync+0x18c/0x190
Code: d2800001 d2800000 d503233f d50323bf (b900003f) 
---[ end trace 0000000000000000 ]---
```

As you can see, this message provides the reason for the crash. In this particular case we see a message about a NULL pointer dereference:

```
Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
```

In my opinion, the most valuable information is the call trace, which shows what happened and where:

```
Call trace:
 faulty_write+0x10/0x20 [faulty]
 ksys_write+0x74/0x110
 __arm64_sys_write+0x1c/0x30
 invoke_syscall+0x54/0x130
 el0_svc_common.constprop.0+0x44/0xf0
 do_el0_svc+0x2c/0xc0
 el0_svc+0x2c/0x90
 el0t_64_sync_handler+0xf4/0x120
 el0t_64_sync+0x18c/0x190
```

The call stack indicates that something went wrong inside faulty_write (faulty_write+0x10/0x20 [faulty]), at offset +0x10. Below is the code for this function:

```
ssize_t faulty_write (struct file *filp, const char __user *buf, size_t count,
                loff_t *pos)
{
        /* make a simple fault by dereferencing a NULL pointer */
        *(int *)0 = 0;
        return 0;
}
```

You can convert this offset to the exact source line using the following commands:

```
addr2line -e faulty.ko 0x10
```

Or, for absolute addresses:

```
addr2line -e faulty.ko ffffffffffffff
```

As a result of running this command, you should get the exact line of code responsible for the crash:

```
addr2line -e faulty.ko 0x10
misc-modules/faulty.c:51
```

The kernel message also provides information about linked modules that may have caused the problem, the kernel "Tainted:" state, the kernel version, and the PID of the process that triggered the crash:

```
Modules linked in: faulty(O) hello(O)
CPU: 0 PID: 107 Comm: sh Tainted: G           O       6.1.44 #1
```

It also provides the processor register state:

```
pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : faulty_write+0x10/0x20 [faulty]
lr : vfs_write+0xc8/0x390
sp : ffffffc008dd3d20
x29: ffffffc008dd3d80 x28: ffffff8001b9cf80 x27: 0000000000000000
x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
x23: 0000000000000006 x22: 0000000000000006 x21: ffffffc008dd3dc0
x20: 000000556f3b9ac0 x19: ffffff8001bc6800 x18: 0000000000000000
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
x5 : 0000000000000001 x4 : ffffffc000785000 x3 : ffffffc008dd3dc0
x2 : 0000000000000006 x1 : 0000000000000000 x0 : 0000000000000000
```

And the memory state:

```
Mem abort info:
  ESR = 0x0000000096000045
  EC = 0x25: DABT (current EL), IL = 32 bits
  SET = 0, FnV = 0
  EA = 0, S1PTW = 0
  FSC = 0x05: level 1 translation fault
Data abort info:
  ISV = 0, ISS = 0x00000045
  CM = 0, WnR = 1
user pgtable: 4k pages, 39-bit VAs, pgdp=0000000041b59000
[0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
```