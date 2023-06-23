---
title:  "ROP and ROLL in Multiple Archs"
date:  2023-03-31
draft:  true
enableToc: true
description: "A journey with ROP access different CPU architectures"
tags:
- misc
image: "images/thumbnails/dell.jpg"

---

Werid machines are the root of all exploitation (not evil!), In fact, It is a really interesting topic that I chose to name my blog after. hence, I will give a little primer on weird machines.

Before going any deeper, let's go through the history of binary exploitation, this will help us understand the advancements upon advancements in the exploitation scene, It all started with buffer overflows, and there is no better way to explain it than quoting the man himself.

> So a buffer overflow allows us to change the return address of a function. In this way we can change the flow of execution of the program.
>
> strcpy() will then copy large_string onto buffer without doing any bounds checking, and will overflow the return address, overwriting it with the address where our code is now located.  Once we reach the end of main and it tried to return it jumps to our code, and execs a shell.
>
> *- Aleph One in "Smashing the Stack for Fun and Profit"*

Solar Designer is known for the first ever ret2libc.
> Hello!
>
> I finally decided to post a return-into-libc overflow exploit. This method has been discussed on linux-kernel list a few months ago (special thanks to Pavel Machek), but there was still no exploit.[^sdesigner]
[^sdesigner]: https://seclists.org/bugtraq/1997/Aug/63

later in 2000, Tim Newsham also did another ret2libc.

> Here’s an overflow exploit [for the lpset bug in sol7 x86] that works on a non-exec stack on x86 boxes It demonstrates how it is possible to thread together several libc calls I have not seen any other exploits for x86 that have done this [^tnewsham]
[^tnewsham]: https://packetstormsecurity.com/files/10025/lpset.overflow.html

couple more years later, Hovav Shacham published "The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls (on the x86)"

> We present new techniques that allow a return-into-libc attack to be mounted on x86 executables that calls no functions at all. Our attack combines a large number of short instruction sequences to build gadgets that allow arbitrary computation. We show how to discover such instruction sequences by means of static analysis. We make use, in an essential way, of the properties of the x86 instruction set.[^hovav]
[^hovav]: https://hovav.net/ucsd/dist/geometry.pdf

We now arrive at the final beast, famously known as return-oriented-programming or ROP. It exploits the fact that any assembly instruction must have a side-effect. cherry picking these side-effects and chaining them together can allow us to build a new program within the original vulnerable program. this new program that we have built is called a "Weird Machine". In fact, this is where the name of this blog had come from.

{{<alert theme="info">}}
It's important to note that, ROP in itself is useless without the intial foothold into the programs instruction pointer, without the ability to redirect program flow, we can't intiate our beautiful orchestra.
{{</alert>}}

# x86_32
# x86_64
# ARM
# MIPS
