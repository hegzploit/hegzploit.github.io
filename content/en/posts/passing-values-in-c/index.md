---
title: "Ways to return function values in C"
date: 2022-03-25
draft: false
enableToc: true
description: "I was having a chit-chat with a friend discussing some C language shenanigans
when he sent me a code snippet, he wanted me fix the code and get it to work in
4 different ways."
---

I was having a chit-chat with a friend discussing some C language shenanigans
when he sent me a code snippet, he wanted me fix the code and get it to work in
4 different ways.

Here is the snippet:

```C
#include <stdio.h>

void calc (int x, int y);
int main(void){
	int x = 10, y = 50;
	printf("sum=%d ", sum);
	printf("mult=%d", mul);
}

void calc (int x, int y){
	int sum = x + y;
	int mul = x * y;
}
```

There are two main takeaways from the above snippet:
- The `calc` function is never called in main.
- Even if we called it in main, the `sum` and `mul` variables are locals to the
scope of `calc`.

The obvious solution to me was to just make these variables globals then we can
just call `calc` in main and we're done, but he wanted me to do it in 4
different ways, that was clearly an exercise of passing values around in C.

## Using Global Variables
```c
#include <stdio.h>

int sum, mul;
void calc (int x, int y);

int main(void){
	int x = 10, y = 50;
	calc(x, y);
	printf("sum=%d ", sum);
	printf("mult=%d", mul);
}

void calc (int x, int y){
	sum = x + y;
	mul = x * y;
}
```
**Output**
> sum=60 mult=500

This is pretty simple, by making the `sum` and `mul` variables global, we just
expand their scope to the whole program.

## Using Pointers

```c
#include <stdio.h>

void calc (int x, int y, int *sum, int *mul);

int main(void){
	int x = 10, y = 50;
	int sum, mul;
	calc(x, y, &sum , &mul);
	printf("sum=%d ", sum);
	printf("mult=%d", mul);
}

void calc (int x, int y, int *sum, int *mul){
	*sum = x + y;
	*mul = x * y;
}
```

In this solution we declared these variables in the `main` function and
passed them by pointers (i.e. we passed a reference to their location in
memory), by doing this we can freely modify a variable from another scope since
we directly access the variable's location in memorey. 

i.e. we dereference a memory address and modify the value that the address is
pointing to.

### Bonus: Passing by Reference (C++)

```C++
#include <stdio.h>

void calc (int x, int y, int &sum, int &mul);

int main(void){
	int x = 10, y = 50;
	int sum, mul;
	calc(x, y, sum , mul);
	printf("sum=%d ", sum);
	printf("mult=%d", mul);

	return 0;
}

void calc (int x, int y, int &sum, int &mul){
	sum = x + y;
	mul = x * y;
}
```

C++ allows us to directly pass the address of `sum` and `mul` without using
pointers, we just pass them by reference. 

That's why I think people should be careful of using the terms "pass-by-pointer"
and "pass-by-reference" interchangeably as these are two different things.

## Using Arrays

```C
#include <stdio.h>

int calc (int x, int y, int *result);

int main(void){
	int x = 10, y = 50;
	int result[2];
	calc(x, y, result);
	printf("sum=%d ", result[0]);
	printf("mult=%d", result[1]);
}

int calc (int x, int y, int *result){
	int sum = x + y;
	int mul = x * y;
	result[0] = sum;
	result[1] = mul;
}
```

Passing values with arrays are useful when our values have the same type, It is
very similar to passing by pointer/reference since we actually pass the address
of the array to the `calc` function, It's values is then modified using the
array notation `my_array[index] = value` which is really equivalent to
`*(my_array + index) = value`.

## Using Structs

```C
#include <stdio.h>

struct Result{
	int sum, mul;
};

struct Result calc (int x, int y);

void main(void){
	int x = 10, y = 50;
	struct Result result = calc(x, y);
	printf("sum=%d", result.sum);
	printf("mult=%d", result.mul);
}

struct Result calc (int x, int y){
	struct Result res;
	res.sum = x + y;
	res.mul = x * y;
	return res;
}
```

C structs are a decent way of passing multiple values around functions,
especially when these values are of different types, we can also get around
typing `Struct Result` a bunch of times by adding a typedef that introduces a new
type in our code, It makes our code a bit cleaner and easier to read.

This is the same code but with introducing the typedef.
```C
#include <stdio.h>

typedef struct Result{
	int sum, mul;
};

Result calc (int x, int y);

int main(void){
	int x = 10, y = 50;
	Result result = calc(x, y);
	printf("sum=%d ", result.sum);
	printf("mult=%d", result.mul);
}

Result calc (int x, int y){
	Result res;
	res.sum = x + y;
	res.mul = x * y;
	return res;
}
```
---

Note: All these solutions are ways to return multiple values from a function, unlike modern languages like python we can't do this in C, another good solution is splitting the `calc` function two two spearate functions where each one of them will return It's result, sometimes this can be better than the above approaches and It's all depending on taste.

```C
#include <stdio.h>

int sum (int x, int y);
int mul (int x, int y);

void main(void){
	int x = 10, y = 50;
	printf("sum=%d ", sum(x,y));
	printf("mult=%d", mul(x,y));
}

int sum (int x, int y){
	int sum = x + y;
	return sum;
}

int mul (int x, int y){
	int mul = x * y;
	return mul;
}
```
