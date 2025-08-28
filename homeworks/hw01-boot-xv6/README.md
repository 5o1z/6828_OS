## Homework 1 - Boot xv6

### Setup

```sh
$ git clone git://github.com/mit-pdos/xv6-public.git
Cloning into 'xv6-public'...
$ cd xv6-public
$ make
```

### Find and break at an address

We can find the address of `_start`, which is kernel entry point by using `nm` command:

```sh
$ nm kernel | grep _start
8010948c D _binary_entryother_start
80109460 D _binary_initcode_start
0010000c T _start
```

Run the kernel inside qemu GDB, and debug it, set a breakpoint at `0x010000c`:

```sh
$ make qemu-gdb
*** Now run 'gdb'.
qemu-system-i386 -serial mon:stdio -drive file=fs.img,index=1,media=disk,format=raw -drive file=xv6.img,index=0,media=disk,format=raw -smp 2 -m 512  -S -gdb tcp::26000
$ gdb
[...]
(gdb) b *0x010000c
Breakpoint 1 at 0x10000c
(gdb) c
Continuing.
The target architecture is set to "i386".
=> 0x10000c:    mov    eax,cr4

Thread 1 hit Breakpoint 1, 0x0010000c in ?? ()
(gdb) i r eax ecx edx ebx esp ebp esi edi eip
eax            0x0                 0
ecx            0x0                 0
edx            0x1f0               496
ebx            0x10094             65684
esp            0x7bdc              0x7bdc
ebp            0x7bf8              0x7bf8
esi            0x10094             65684
edi            0x0                 0
eip            0x10000c            0x10000c
(gdb) x/24w $esp
0x7bdc: 0x00007d87      0x00000000      0x00000000      0x00000000
0x7bec: 0x00000000      0x00000000      0x00000000      0x00000000
0x7bfc: 0x00007c4d      0x8ec031fa      0x8ec08ed8      0xa864e4d0
0x7c0c: 0xb0fa7502      0xe464e6d1      0x7502a864      0xe6dfb0fa
0x7c1c: 0x16010f60      0x200f7c78      0xc88366c0      0xc0220f01
0x7c2c: 0x087c31ea      0x10b86600      0x8ed88e00      0x66d08ec0
```

### Exercise: What is on the stack?

<details>
<summary><strong>Where in `bootasm.S` is the stack pointer initialized?</strong></summary>

```x86asm
  # Set up the stack pointer and call into C.
  movl    $start, %esp # Move start address (0x7c00) to esp
  call    bootmain
```

</details>

<details>
<summary><strong>Step through the call to bootmain(), what is on the stack?</strong></summary>


First set a breakpoint at `0x7c43`, which setup the stack frame and call `bootmain`:

```gdb
(gdb) b *0x7c43
Breakpoint 1 at 0x7c43
(gdb) c
Continuing.
The target architecture is set to "i386".
=> 0x7c43:      mov    esp,0x7c00

Thread 1 hit Breakpoint 1, 0x00007c43 in ?? ()
(gdb) i r eax ecx edx ebx esp ebp esi edi eip
eax            0x0                 0
ecx            0x0                 0
edx            0x80                128
ebx            0x0                 0
esp            0x6f00              0x6f00
ebp            0x0                 0x0
esi            0x0                 0
edi            0x0                 0
eip            0x7c43              0x7c43
(gdb) x/4x $esp
0x6f00: 0xf000d009      0x00000000      0x00006f5e      0x00008148
(gdb) si
=> 0x7c48:      call   0x7d3d
0x00007c48 in ?? ()
(gdb) i r eax ecx edx ebx esp ebp esi edi eip
eax            0x0                 0
ecx            0x0                 0
edx            0x80                128
ebx            0x0                 0
esp            0x7c00              0x7c00
ebp            0x0                 0x0
esi            0x0                 0
edi            0x0                 0
eip            0x7c48              0x7c48
(gdb) x/4x $esp
0x7c00: 0x8ec031fa      0x8ec08ed8      0xa864e4d0      0xb0fa7502
```

Step into `bootmain()` function:

```gdb
(gdb) si
=> 0x7d3d:      push   ebp
0x00007d3d in ?? ()
(gdb) x/4x $esp
0x7bfc: 0x00007c4d      0x8ec031fa      0x8ec08ed8      0xa864e4d0
```

And these instruction will setup a stack frame for `bootmain()`:

```gdb
(gdb) x/6i 0x7d3d
=> 0x7d3d:      push   ebp
   0x7d3e:      mov    ebp,esp
   0x7d40:      push   edi
   0x7d41:      push   esi
   0x7d42:      push   ebx
   0x7d43:      sub    esp,0x10
```

At the end of `bootmain()` function, it will call `entry()`, which will push the return value `0x7d87` to the stack:

```gdb
(gdb) x/2i 0x7d81
   0x7d81:      call   DWORD PTR ds:0x10018
   0x7d87:      lea    esp,[ebp-0xc]
```

</details>

<details>
<summary><strong>Step to the entry point of the kernel, What is on the stack?</strong></summary>

Set a breakpoint at `0x7d81`, check the stack and register there then step into `entry` function:

```gdb
(gdb) i r eax ecx edx ebx esp ebp esi edi eip
eax            0x0                 0
ecx            0x0                 0
edx            0x1f0               496
ebx            0x10094             65684
esp            0x7be0              0x7be0
ebp            0x7bf8              0x7bf8
esi            0x10094             65684
edi            0x0                 0
eip            0x7d81              0x7d81
(gdb) x/24x $esp
0x7be0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7bf0: 0x00000000      0x00000000      0x00000000      0x00007c4d
0x7c00: 0x8ec031fa      0x8ec08ed8      0xa864e4d0      0xb0fa7502
0x7c10: 0xe464e6d1      0x7502a864      0xe6dfb0fa      0x16010f60
0x7c20: 0x200f7c78      0xc88366c0      0xc0220f01      0x087c31ea
0x7c30: 0x10b86600      0x8ed88e00      0x66d08ec0      0x8e0000b8
(gdb) si
=> 0x10000c:    mov    eax,cr4
(gdb) x/24x $esp
0x7bdc: 0x00007d87      0x00000000      0x00000000      0x00000000
0x7bec: 0x00000000      0x00000000      0x00000000      0x00000000
0x7bfc: 0x00007c4d      0x8ec031fa      0x8ec08ed8      0xa864e4d0
0x7c0c: 0xb0fa7502      0xe464e6d1      0x7502a864      0xe6dfb0fa
0x7c1c: 0x16010f60      0x200f7c78      0xc88366c0      0xc0220f01
0x7c2c: 0x087c31ea      0x10b86600      0x8ed88e00      0x66d08ec0
```

</details>

<details>
<summary><strong>Stack data</strong></summary>


```gdb
0x7bdc: 0x00007d87 # entry return address
0x7bdc: 0x00000000 # end of moving $esp by 0x10 bytes
...
0x7bec: 0x00000000 # EBX & start of moving $esp by 0x10 bytes
0x7bf0: 0x00000000 # ESI
0x7bf4: 0x00000000 # EDI
0x7bf8: 0x00000000 # EBP
0x7bfc: 0x00007c4d # Return address
0x7bf8: 0x8ec031fa # Not the stack
```

</details>
