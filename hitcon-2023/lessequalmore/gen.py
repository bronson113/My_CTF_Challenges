import os 
from sage.all import *
flag = "hitcon{r3vErs1ng_0n3_1ns7ruction_vm_1s_Ann0ying_c9adf98b67af517}"

# idea: large matrix multiplication
# rev -> extract the matrix and reverse the operations to get the flag
# pwn ->
##  input is done in a loop -> out of bound write
##  small memory -> overwrite register due to memory layout
#   out of bound read/write on stack -> ROP (how though?) -> RCE
# 

l = len(flag)
m = [Matrix(ZZ, flag[i:i+8].encode()) for i in range(0, l, 8)]
blocks = len(m)
assert blocks == l // 8
# get random matrix from 0 to 5 size l * l
key1 = random_matrix(ZZ, 8, algorithm='unimodular', upper_bound=4)
key2 = random_matrix(ZZ, 8, algorithm='unimodular', upper_bound=4)
print(l, blocks)
print(f"key1:\n{key1}\nkey2:\n{key2}\n")
# assert that M is invertiable
assert key1.is_invertible()
assert key2.is_invertible()
#print("inverse:\n", key1.inverse(), key2.inverse())

ans = []
for i in range(0, blocks):
#    print(key1 * key2 * m[i].transpose())
    ans.extend(key2 * key1 * m[i].transpose())

#print(key1*key2)
print(f"total key:\n{key2*key1}\ndecryption key:\n{(key2*key1).inverse()}")

label = 0
def call(f):
    global label
    label += 1
    return f"""
    sub SP, 1
    mov A, .L{label}
    store A, SP
    jmp {f}
    .L{label}:
"""

def define_func(l):
    return f"""{l}:
"""

def push(reg):
    return f"""
    sub SP, 1
    mov A, {reg}
    store A, SP
"""

def pop(reg):
    return f"""
    load {reg}, SP
    add SP, 1
"""

def prelog(usedc, stackd):
    ops = "mov A, SP\n"
    for i in range(usedc):
        ops += push("BCD"[i])
    ops += f"""
    {push('BP')}
    mov BP, SP
    sub SP, {stackd}
"""
    return ops
    
def epilog(usedc, stackd):
    ops = "mov SP, BP\n"
    ops += pop("BP")
    for i in range(usedc): 
        ops += pop("BCD"[:usedc][::-1][i])
    ops += f"""
    load A, SP
    add SP, 1
    jmp A
"""
    return ops

# B -> dst
# C -> src
def memcpy():
    return f"""
    mov D, 0
    .loopmemcpy:
    mov A, BP
    add A, 3
    load A, A
    add A, D
    mov B, BP
    add B, 2
    load B, B
    add B, D
    load B, B
    store B, A
    add D, 1
    jne .loopmemcpy, D, 8
    """
    

# B -> loc of flag (8 byte)
# C -> loc of output buf (8 byte)
def matmult(key):
    ops = ""
    for i in range(8):
        ops += f"""
            mov A, BP
            add A, 1
            load C, A
            add C, {i}
            mov A, 0
            store A, C
        """
        for j in range(8):
            if key[i, j] == 0:
                continue

            ops += f"""
            mov A, BP
            add A, 2
            load A, A
            add A, {j}
            load A, A
            load B, C
            """ + f"{['add', 'sub'][key[i, j] > 0]} B, A\n" * abs(key[i, j]) +            """
            store B, C
            """
    return ops

def targets():
    return "\n".join([f".long {i[0]}" for i in ans])
    
# calling convention
# B for ret val
# B, C, D for args
eir = f"""
{define_func("main")}
mov C, 0
mov D, 0
mov B, prompt
{call('print_buffer')}
mov B, input
{call('input_flag')}
mov B, prompt2
{call('print_buffer')}
mov B, input
{call('print_buffer')}
.checkall:
mov B, 0
mov B, input
add B, D
mov C, buf
{call('matmult1')}
mov B, input
add B, D
mov C, buf
{call('memcpy')}

mov B, 0
mov B, input
add B, D
mov C, buf
{call('matmult2')}
mov B, input
add B, D
mov C, buf
{call('memcpy')}

add D, 8
jne .checkall, D, 64

mov D, 0
.checkans:

mov B, input
add B, D
load B, B
mov C, target
add C, D
load C, C
jne .losing, B, C
add D, 1
jne .checkans, D, 64

.winning:
mov B, win
{call('print_buffer')}
exit

.losing:
mov B, lose
{call('print_buffer')}
exit

{define_func("input_flag")}
{prelog(1, 0)}
.forloop1:
mov A, 0
getc A
jeq .exit1, A, 10
store A, B
add B, 1
jmp .forloop1
.exit1:
mov A, 0
store A, B
{epilog(1, 0)}
{define_func("print_buffer")}
{prelog(1, 0)}
.forloop2:
load A, B
jeq .exit2, A, 0
putc A
add B, 1
jmp .forloop2
.exit2:
putc 10
{epilog(1, 0)}
{define_func("matmult1")}
{prelog(2, 0)}
{matmult(key1)}
{epilog(2, 0)}
{define_func("matmult2")}
{prelog(2, 0)}
{matmult(key2)}
{epilog(2, 0)}
{define_func("memcpy")}
{prelog(3, 0)}
{memcpy()}
{epilog(3, 0)}
.data
 input: 
 .string "{(chr(92)+'x00')*64}"
 buf: 
 .string "{(chr(92)+'x00')*16}"
 target:
 {targets()}
 prompt:
 .string "*** Flag Checker ***"
 prompt2:
 .string "You entered:"
 win:
 .string "Congrats! You got the flag!"
 lose:
 .string "Sorry, wrong flag!"
"""


with open("chal.eir", "w") as f:
    f.write(eir)

# compile
os.system("elvm/out/elc -subleq chal.eir > chal.eir.subleq")

# test run
os.system("./interpreter chal.eir.subleq")

# should solve
os.system("python3 solve.py")
