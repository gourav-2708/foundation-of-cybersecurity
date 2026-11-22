# Experiment 4: Buffer Overflow Exploit in C

## Theory

A stack-based buffer overflow occurs when a program copies more data into a fixed-size buffer than it can hold without validating the input bounds.

In the x86/x64 calling convention, local variables are generally stored on the stack near the saved frame pointer (RBP/EBP) and the saved return address (RIP/EIP). Writing beyond the allocated buffer may overwrite nearby stack data, including the stored return address.

When the function returns, the processor normally uses the stored return address to continue execution in the calling function. If this address is overwritten, program execution may crash or be redirected.

## Stack Layout

Low Memory Addresses

```text
+-----------------------------+
| char buffer[64]             |  <-- Buffer Start
+-----------------------------+
| Saved Frame Pointer (EBP)   |  <-- 4 / 8 bytes
+-----------------------------+
| Saved Return Address (EIP)  |  <-- Possible overwrite target
+-----------------------------+
```

High Memory Addresses

## Vulnerable Source Code (vuln.c)

```c
#include <stdio.h>
#include <string.h>

void secret_function()
{
    printf("[+] Vulnerability Exploited! Target reached.\n");
}

void vulnerable_function()
{
    char buffer[64];

    printf("Enter input string: ");

    // gets() does not perform boundary checking
    gets(buffer);

    printf("You entered: %s\n", buffer);
}

int main()
{
    printf("[*] Starting program...\n");

    vulnerable_function();

    printf("[-] Program exited normally.\n");

    return 0;
}
```

## Compilation and Demonstration

To study the behavior of a buffer overflow in a controlled laboratory environment, the program can be compiled with specific compiler protections disabled.

### Compile in 32-bit x86 Mode

```bash
gcc -m32 -fno-stack-protector -z execstack -no-pie vuln.c -o vuln
```

### Meaning of Options

- `-m32`: Compiles the program as a 32-bit executable.
- `-fno-stack-protector`: Disables stack canaries.
- `-z execstack`: Marks the stack as executable.
- `-no-pie`: Disables Position Independent Executable (PIE), making program addresses more predictable.

### Generate an Overflowing Input

An input larger than the 64-byte buffer can demonstrate the overflow:

```bash
python3 -c "print('A' * 100)" | ./vuln
```

The program may terminate with an error such as:

```text
Segmentation fault (core dumped)
```

This occurs because data has been written beyond the allocated buffer and may have corrupted important stack information.

### Examining the Program Using GDB

Start the program using GDB:

```bash
gdb ./vuln
```

Inside GDB, the address of `secret_function()` can be inspected using:

```text
(gdb) print secret_function
```

Example output:

```text
$1 = {void ()} 0x08049182
```

> **Note:** The exact address may differ depending on the compiler, operating system, architecture, and binary configuration.

In a controlled laboratory demonstration, the stack layout and offset can then be studied to understand how overwriting data beyond the buffer affects the saved return address.

## Mitigation Strategies

### 1. Safe Library Functions

Avoid unsafe functions such as:

- `gets()`
- `strcpy()`
- `sprintf()`

Use bounded alternatives such as:

- `fgets()`
- `strncpy()`
- `snprintf()`

Example:

```c
fgets(buffer, sizeof(buffer), stdin);
```

`fgets()` restricts the amount of data written into the buffer and helps prevent writing beyond its allocated size.

### 2. Stack Canaries

Modern compilers can insert a special random value called a stack canary between local buffers and important stack information. Before a function returns, the program checks whether the canary value has changed.

If the value has been modified, the program terminates with an error such as:

```text
*** stack smashing detected ***: terminated
Aborted (core dumped)
```

Because the canary sits between the buffer and the saved return address, an overflow that reaches the return address must first overwrite the canary. The check therefore detects the overflow before the corrupted return address is used. Stack canaries are enabled by default in most modern GCC builds; they were turned off in this experiment with `-fno-stack-protector`. They can be enabled explicitly with:

```bash
gcc -fstack-protector-strong vuln.c -o vuln
```

### 3. Non-Executable Stack (NX / DEP)

The NX (No-eXecute) bit, also called Data Execution Prevention (DEP), marks memory regions such as the stack as non-executable. Even if an attacker places machine code inside the buffer, the processor refuses to execute it and the program crashes instead.

This protection was disabled in this experiment with `-z execstack`. Modern compilers and linkers produce a non-executable stack by default, which can also be requested explicitly:

```bash
gcc -z noexecstack vuln.c -o vuln
```

### 4. Address Space Layout Randomization (ASLR)

ASLR is an operating-system feature that loads the stack, heap, and shared libraries at different random addresses each time a program runs. An attacker can no longer rely on a fixed address, such as the address of `secret_function()` found in GDB, because the address changes between executions.

The current ASLR setting on Linux can be checked with:

```bash
cat /proc/sys/kernel/randomize_va_space
```

| Value | Meaning |
| :-: | --- |
| `0` | ASLR disabled |
| `1` | Stack, shared libraries, and memory mappings randomized |
| `2` | Full randomization, including the heap (default on most distributions) |

### 5. Position Independent Executables (PIE)

ASLR only randomizes the program's own code if the executable is compiled as a Position Independent Executable. With PIE, functions such as `secret_function()` are loaded at a different base address on every run.

This protection was disabled in this experiment with `-no-pie`. PIE is the default in most modern GCC builds and can be requested explicitly with:

```bash
gcc -fPIE -pie vuln.c -o vuln
```

### Compiling with All Protections Enabled

The secure version of the program replaces `gets()` with `fgets()` and is compiled with all of the above protections:

```bash
gcc -fstack-protector-strong -z noexecstack -fPIE -pie vuln.c -o vuln_secure
```

The protections applied to a compiled binary can be verified using the `checksec` tool:

```bash
checksec --file=./vuln_secure
```

## Conclusion

A stack-based buffer overflow occurs when a program writes more data into a fixed-size buffer than it can hold, overwriting nearby stack data such as the saved frame pointer and return address. In this experiment, the vulnerable program using `gets()` was compiled with stack protections disabled, and an oversized input caused a segmentation fault, demonstrating how unchecked input corrupts the stack.

The experiment also shows that buffer overflows can be prevented by combining secure coding practices with compiler and operating-system defenses. Using bounded functions such as `fgets()`, along with stack canaries, a non-executable stack, ASLR, and PIE, makes it significantly harder for an overflow to crash a program or redirect its execution.
