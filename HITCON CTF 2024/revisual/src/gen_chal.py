import random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from fractions import Fraction

# key = random.sample(range(25), k=24)
key = [
    19,
    9,
    8,
    15,
    3,
    18,
    17,
    10,
    23,
    5,
    0,
    6,
    24,
    14,
    12,
    11,
    2,
    13,
    16,
    4,
    7,
    1,
    21,
    22,
]
print(key)

flag = b"hitcon{hidden_calculation_through_varying_shader_variables_auto-magical_interpolation_0c4ea0d9d4d9518}"

# sbox = list(range(25))
# random.shuffle(sbox)
# inv_sbox = [sbox.index(i) for i in range(25)]

sbox = [
    4,
    20,
    23,
    13,
    11,
    0,
    15,
    1,
    14,
    21,
    9,
    19,
    8,
    3,
    17,
    24,
    16,
    6,
    22,
    10,
    7,
    18,
    2,
    5,
    12,
]
inv_sbox = [
    5,
    7,
    22,
    13,
    0,
    23,
    17,
    20,
    12,
    10,
    19,
    4,
    24,
    3,
    8,
    6,
    16,
    14,
    21,
    11,
    1,
    9,
    18,
    2,
    15,
]
print(sbox)
print(inv_sbox)


def apply_sbox(x, sbox):
    _x = int(x)
    return x + (sbox[_x] - _x)


for i in range(25):
    print(apply_sbox(i, sbox), apply_sbox(i + 0.1, sbox), apply_sbox(i + 0.9, sbox))


def lerp(a, b, x):
    # print(a, int(a + (b - a) * x), b)
    res = a + (b - a) * x
    return res


def lerp3(a, b, c, x, y):
    # print(a, b, c, x, y)
    res = (1 - x - y) * a + x * b + y * c
    return res


pixel_offset = 1 / 650 / 2
multi = 1 / 25
goal1 = [
    (
        i,
        i + 1,
        i + 2,
        lerp(
            apply_sbox(key[i], sbox) * multi,
            apply_sbox(key[i + 1], sbox) * multi,
            apply_sbox(key[i + 2], sbox) / 25 + pixel_offset,
        ),
    )
    for i in range(0, 9, 3)
]
# goal2 = [
#         (
#             *(a, b, c, x, y),
#             lerp3(
#                 key[a] * multi,
#                 key[b] * multi,
#                 key[c] * multi,
#                 key[x] / 50 + pixel_offset / 2,
#                 key[y] / 50 + pixel_offset / 2,
#                 ),
#             f"temp{i}",
#             )
#         ]

temps = []
seen = set()
temp_count = 0
for i in range(200):
    a, b, x = random.sample(range(24), k=3)
    seen |= {a, b, x}
    l = lerp(
        apply_sbox(key[a], sbox) * multi,
        apply_sbox(key[b], sbox) * multi,
        apply_sbox(key[x], sbox) / 25 + pixel_offset,
    )
    print(Fraction(str(l)).limit_denominator())
    temps.append(
        (
            a,
            b,
            x,
            l,
            f"{i}",
            f"temp{i}",
        )
    )

    if len(seen) == len(range(24)):
        temp_count = i
        print(seen)
        break
print(temps)

goal2 = []
seen2 = set()
seen_pair = set()
for i in range(temp_count * 10):
    a, b, c = random.sample(temps, k=3)
    labels = (i[-1] for i in [a, b, c])
    if labels in seen_pair:
        continue
    seen_pair.add(labels)
    seen2 |= set(labels)
    x, y = random.sample(range(25), k=2)
    print(a[3], b[3], c[3])
    res = lerp3(
        apply_sbox(a[3] * 25, sbox) / 25,
        apply_sbox(b[3] * 25, sbox) / 25,
        apply_sbox(c[3] * 25, sbox) / 25,
        apply_sbox(x, sbox) / 50 + pixel_offset / 2,
        apply_sbox(y, sbox) / 50 + pixel_offset / 2,
    )
    print(f"calc_canvas.calc_tri({a[3]*25}, {b[3]*25}, {c[3]*25}, {x}, {y}) == {res}")
    goal2.append((a, b, c, x, y, res))
    if len(seen2) == len(temps):
        print(seen2)
        break

# for a, b, c, l in goal1:
#     print(f"res += abs({l} - calc_canvas.calc_bi(key[{a}], key[{b}], key[{c}]));")

print("for script.js\n\n")
for a, b, x, _, _, label in temps:
    print(f"let {label} = calc_canvas.wtf(key[{a}], key[{b}], key[{x}]) * 25;")
print("let res = 0;")

for a, b, c, x, y, l in goal2:
    print(f"res += abs({l} - calc_canvas.gtfo({a[-1]}, {b[-1]}, {c[-1]}, {x}, {y}));")


print(
    """
  if (res > 0.00001) {
    return null;
  }
  s = "";
"""
)
key_stage2 = []
aes_key = SHA256.new()
s = ""
for i in range(20):
    a, b, c = random.sample(range(24), k=3)
    l = round(
        lerp(
            apply_sbox(key[a], sbox) * multi,
            apply_sbox(key[b], sbox) * multi,
            apply_sbox(key[c], sbox) / 25 + pixel_offset,
        )
        * 100000,
    )
    key_stage2.append((a, b, c, l))
    print(
        f"s += Math.round(calc_canvas.wtf(key[{a}], key[{b}], key[{c}])*100000).toString();"
    )
    s += str(l)
for i in range(20):
    a, b, c, x, y = random.sample(range(24), k=5)
    l = round(
        lerp3(
            apply_sbox(key[a], sbox) / 25,
            apply_sbox(key[b], sbox) / 25,
            apply_sbox(key[c], sbox) / 25,
            apply_sbox(key[x], sbox) / 50 + pixel_offset / 2,
            apply_sbox(key[y], sbox) / 50 + pixel_offset / 2,
        )
        * 100000
    )
    key_stage2.append((a, b, c, x, y, l))
    print(
        f"s += Math.round(calc_canvas.gtfo(key[{a}], key[{b}], key[{c}], key[{x}], key[{y}])*100000).toString();"
    )
    s += str(l)
print(s)
aes_key.update(s.encode())
aes_key_bytes = aes_key.digest()
print(key_stage2)
print(aes_key_bytes.hex())

cipher = AES.new(key=aes_key_bytes[:64], mode=AES.MODE_CBC)
enc = cipher.encrypt(pad(flag, 16))
print(enc.hex())
print(cipher.IV.hex())

print(AES.new(key=aes_key_bytes, mode=AES.MODE_CBC, iv=cipher.IV).decrypt(enc))

for i in range(20):
    a, b, c, x, y = random.sample(range(24), k=5)
    l = round(
        lerp3(
            key[a] * multi,
            key[b] * multi,
            key[c] * multi,
            key[x] / 50 + pixel_offset / 2,
            key[y] / 50 + pixel_offset / 2,
        )
        * 100000,
    )
    key_stage2.append((a, b, c, x, y, l))
    print(
        f"s += Math.round(calc_canvas.gtfo(key[{a}], key[{b}], key[{c}], key[{x}], key[{y}])*100000).toString();"
    )
    s += str(l)

print("\n\nfor solve.sage\n\n")
print(")\ngoal = (")
for a, b, c, x, y, l in goal2:
    print(f"({l}, {a[-2]}, {b[-2]}, {c[-2]}, {x}, {y}),")

print("\ngoal1 = (")
for a, b, x, _, label2, label in temps:
    print(f"(temp[{label2}], key[{a}], key[{b}], key[{x}]),")
print(")")
