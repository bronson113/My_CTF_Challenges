# ctr - cbc - ctr
# but the chaining is done from ctr output
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long, long_to_bytes
from functools import reduce
from pwn import *
from sage.all import matrix, vector, GF
import os


BLOCK_SIZE = 16

def oracle(p, ct):
    p.sendline(b"2")
    p.sendline(ct.hex())

def oracle_res(p, count):
    result = []
    for i in range(count):
        p.recvuntil(b">> ")
        res = p.recvline()
        if b"Something went wrong" in res:
            result.append(False)
        else:
            result.append(True)
    return result


def main():
#    p = remote("127.0.0.1", "5003")
    p = process(["python3", "./src/chal.py"])
    # p = remote("pcbcrevenge.chal.hitconctf.com", 3000)
    p.recvuntil(b"valid certificate: ")
    cipher_text = bytes.fromhex(p.recvline().decode())
    print(cipher_text)


    # get data to work with 
    while True:

        # we need BLOCK_SIZE entries to get enough dimension
        # and some extra for buffer to decrypt out each pt
        working_set_count = BLOCK_SIZE * 8 + 10
        # (pt, ct, pos)
        ptcts = [[] for i in range(working_set_count)]
        for i in range(2):
            p.sendline(b"1")
            p.sendline(str(working_set_count*BLOCK_SIZE-1))
            p.recvuntil(b"certificate for ")
            pt = bytes.fromhex(p.recvline().strip()[:-1].decode())+b"\x01" #padding
            ct = bytes.fromhex(p.recvline().decode())
            iv, ct = ct[:16], ct[16:]
            print(pt[:32].hex(), ct[:32].hex())

            acc = iv
            for j in range(working_set_count):
                partial_pt = pt[j*BLOCK_SIZE:j*BLOCK_SIZE+BLOCK_SIZE]
                partial_ct = ct[j*BLOCK_SIZE:j*BLOCK_SIZE+BLOCK_SIZE]
                actual_pt = xor(partial_pt, acc)
                chaining_number = xor(partial_pt, partial_ct)
                ptcts[j].append((actual_pt, partial_ct, xor(actual_pt, partial_ct), partial_pt, acc))
                acc = chaining_number


        valid = True
        # check span
        for i in range(working_set_count):
            all_other = ptcts[:i] + ptcts[i+1:-1]
            nums = [list(map(int, f"{bytes_to_long(xor(x[0][2], x[1][2])):0128b}")) for x in all_other]
            m = matrix(GF(2), nums)
            if len(m.pivot_rows()) < 128:
                print(len(m.pivot_rows()))
                print("invalid")
                valid = False
                break

        if valid: break


    def prep_query(cur_index: int):
        working_set = ptcts[:cur_index] + ptcts[cur_index+1:-1]
        nums = [list(map(int, f"{bytes_to_long(xor(x[0][2], x[1][2])):0128b}")) for x in working_set]

        # relative change
        chain_base = reduce(lambda acc, x: acc ^ bytes_to_long(x[0][2]), working_set, 0)

        m = matrix(GF(2), nums)
        return m, chain_base

    def gen_query(target: bytes, cur_index: int, query_ct: bytes, iv: bytes, M, chain_base):
        working_set = ptcts[:cur_index] + ptcts[cur_index+1:-1]

        # diff to apply to the last block
        actual_target = bytes_to_long(target) ^ bytes_to_long(ptcts[-1][0][0])
        # account for current ct
        actual_target ^= bytes_to_long(query_ct)
        # account for selecting the blocks, act as base
        actual_target ^= chain_base 

        actual_target ^= bytes_to_long(iv)

        res_vec = M.solve_left(vector(map(int, f"{actual_target:0128b}")))
        assert(len(res_vec) == len(working_set))

        query_t = [working_set[i][int(j)][1] for (i, j) in enumerate(res_vec)]
        query_t.insert(cur_index, query_ct)
        query_t.append(ptcts[-1][0][1])

        return b"".join(query_t)


    iv, ct = cipher_text[:16], cipher_text[16:]

    # for testing
    for i in range(1, 9):
        target = xor(bytes([i]*16), bytes([1]*(16-i)+[0]*(i)), ptcts[i][0][0])
        M, chain_base = prep_query(i)
        oracle(p, iv+gen_query(target, i, ptcts[i][0][1], iv, M, chain_base))
    print(oracle_res(p, 8)) #should be all true

    # # now we have a chain_base and sets of vector to work with
    # # we can start padding oracle =D
    # # we will substitute each block in place one by one
    flag = b""
    acc = iv
    for block in range(len(ct)//BLOCK_SIZE):
        guess = []
        cur_ct = ct[block*BLOCK_SIZE:block*BLOCK_SIZE+BLOCK_SIZE]
        for l in range(1, 17):
            M, chain_base = prep_query(block)
            for c in range(256):
                # print(bytes(guess+[c])[::-1])
                target = xor(bytes([c]+guess[::-1]).rjust(16,b"\x00"), bytes([l]*16))
                oracle(p, iv+gen_query(target, block, cur_ct, iv, M, chain_base))

            res = oracle_res(p, 256)

            for c in range(256):
                if res[c]:
                    guess.append(c)
                    break
            print(bytes(guess[::-1]))
        cur_block_leak = xor(bytes(guess[::-1]), acc)
        acc = xor(cur_block_leak, cur_ct)
        flag += cur_block_leak
        print(flag)

    # flag = ""
    # for index in range(len(ct) // BLOCK_SIZE):
    # print(flag)


if __name__ == "__main__":
    main()





