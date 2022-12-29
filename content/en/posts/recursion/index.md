---
title: "Optimizing Recursion"
date: 2020-09-24T15:52:30+02:00
enableToc: true
description: "Recursion is a pretty improtant topic in programming and it's not that hard to grasp or even implement, but how about actually using it correctly?"
image: "images/header/recursion_header.png"
libraries:
- mathjax
---

In this blog post i will try to explain the basic concept of recursion and then show why recursion can be so inefficient and how to optimize it using **Call Tail Optimization!**

## Normal Recursion, A Factorial Example
Most of us tech nerds have already dealt with the good 'ol recursion, let's refresh our understanding using the iconic factorial program.
$$0! = 1$$
$$n! = n (n-1)!$$
Python Implementation:
```Python
def fact(x):
	if (x==0):
		return 1
	else:
		return x * fact(x-1)
```

*But python is just too mainstream and overrated, let's use Lisp!*

```Scheme
(define (fact x)
  (if (= x 0)
      1
	  (* x (fact (- x 1)))))
```

ain't Scheme just too beautiful?
Now, let's inspect the program behavior!

## Tracing The Recursion
let's say we want to execute `(fact 5)` which supposedly evaluates to 120.
here is the trace of the factorial operation:
```Scheme
(fact 5)
(* 5 (fact 4))
(* 5 (* 4 (fact 3)))
(* 5 (* 4 (* 3 (fact 2))))
(* 5 (* 4 (* 3 (* 2 (fact 1)))))
(* 5 (* 4 (* 3 (* 2 (* 1 (fact 0))))))
(* 5 (* 4 (* 3 (* 2 (* 1 1)))))
(* 5 (* 4 (* 3 (* 2 1))))
(* 5 (* 4 (* 3 2)))
(* 5 (* 4 6))
(* 5 24)
120
```

here's the pythonic version for those who are struggling with lisp (it's way easier believe me)
```Python
fact(5)
5 * fact(4)
5 * (4 * fact(3))
5 * (4 * (3 * fact(2)))
5 * (4 * (3 * (2 * fact(1))))
5 * (4 * (3 * (2 * (1 * fact(0)))))
5 * (4 * (3 * (2 * (1 * 1))))
5 * (4 * (3 * (2 * 1)))
5 * (4 * (3 * 2))
5 * (4 * 6)
5 * 24
120
```
Did you figure out the flaw of our simple recursion implementation yet?

It's pretty simple, the way we expand the factorial on each iteration so that it grows and keeps growing until we fully expand it is just so inefficient and wastes memory space.

The waste of memory space comes from the fact that each call of `(fact x)` will allocate a new stack frame to store its data, so we have used around 6 stack frames for this simple calculation, allocating and popping stack frames is a relatively intensive operation for the CPU.

The source of this flaw is the multiplication that we are performing with our recurred call.

So Tail Call Optimization or Tail Recursion are just fancy names for a simple rule we need to follow in order to optimize our recursive functions.

*"The recurred call shouldn't be combined with other operations"*

i.e: we need to move the multiplication operator out of the recurred call in the factorial function

## Using Tail Recursion
let's rewrite the factorial function in Tail Recursion:
```Scheme
(define (fact-tail x accum)
  (if (= x 0) accum 
  (fact-tail (- x 1) (* x accum))))

(define (fact x) (fact-tail x 1))
```
### Pythonic version:
```Python
def factTail(x, accum):
	if (x == 0):
		return accum
	else:
		return factTail(x-1, x*accum)
def fact(x):
	return factTail(x, 1)
```
what we did in that snippet above is pretty simple, we just split the work across two functions, the first function `(fact-tail x accum)` will iterate and the second function `(fact x)` will call the first function and returns the value of each iteration (we have also moved the multiplication operation to it's own variable) so we basically have no extra operations going on, *in fact calling `(fact 0)` is now the same as calling `(fact 10000)` in terms of memory size.*

let's step through each iteration and see for ourselves how great is Tail Recursion:
```Scheme
(fact 5)
(fact-tail 5 1)
(fact-tail 4 5)
(fact-tail 3 20)
(fact-tail 2 60)
(fact-tail 1 120)
(fact-tail 0 120)
120
```
Pythonic Version:
```Python
fact(5)
factTail(5, 1)
factTail(4, 5)
factTail(3, 20)
factTail(2, 60)
factTail(1, 120)
factTail(0, 120)
```
is this even recursion anymore, that's just **fancy iteration!**

we have used recursion in such a way that we store all the data to perform our evalutaion in each individual reccured call!
All Hail Tail Call Optimization!

## More Tail Recursion!
here is one more example with the infamous fibonacci function in both normal Recursion and then Tail Recursion:

*(you try to implement it in python this time :p)*
### Normal Recursion
```Scheme
(define (fib x)
  (cond ((= x 0) 0)
  		((= x 1) 1)
  		(else (+ (fib (- x 1)) (fib (- x 2))))))
```
### Tail Recursion
```Scheme
(define (fib x)
    (fib-iter x 0 1))

(define (fib-iter x a b)
    (cond ((= x 0) a)
    ((= x 1) b)
    (else (fib-iter (- x 1) b (+ a b)))))
```
*All Hail The Tail Recursion*
