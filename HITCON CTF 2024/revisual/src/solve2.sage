from fractions import Fraction

def lerp(a, b, x):
    # print(a, int(a + (b - a) * x), b)
    return round(a + (b - a) * x, 9)


def lerp3(a, b, c, x, y):
    # print(a, b, c, x, y)
    res = (1 - x - y) * a + x * b + y * c
    return round(res, 9)

def inv_sbox(x):
    inv = [5, 7, 22, 13, 0, 23, 17, 20, 12, 10, 19, 4, 24, 3, 8, 6, 16, 14, 21, 11, 1, 9, 18, 2, 15]
    return x - int(x) + int(inv[int(x)])

def sbox(x):
    box = [4, 20, 23, 13, 11, 0, 15, 1, 14, 21, 9, 19, 8, 3, 17, 24, 16, 6, 22, 10, 7, 18, 2, 5, 12]
    return x - int(x) + int(box[int(x)])



pixel_offset = 1 / 650 / 2
multi = 1 / 25
mapping = [0 for i in range(25**3)]
for i in range(25):
    for j in range(25):
        for k in range(25):
            mapping[i * 625 + j * 25 + k] = lerp(
                i * multi, j * multi, k / 25 + pixel_offset
            )



goal = (
(0.5353483786982249, 8, 22, 11, 21, 18),
(0.0426426627218935, 11, 4, 0, 4, 0),
(0.35424160946745553, 15, 9, 23, 12, 22),
(0.1316865562130177, 11, 15, 17, 9, 0),
(0.688061550295858, 9, 24, 17, 1, 2),
(0.7146429230769231, 20, 21, 22, 10, 2),
(0.8419481301775147, 21, 14, 1, 10, 3),
(0.13850963313609468, 11, 21, 10, 13, 23),
(0.1650677633136095, 23, 5, 20, 24, 16),
(0.7636094201183432, 10, 13, 6, 10, 2),
(0.771196426035503, 19, 24, 10, 4, 9),
(0.40248414201183436, 20, 19, 17, 24, 0),
(0.4820614319526627, 0, 25, 12, 15, 7),
(0.45585272189349113, 3, 1, 13, 23, 1),
(0.5789388639053255, 25, 13, 0, 7, 17),
(0.4070449112426035, 13, 21, 8, 19, 4),
(0.5890136686390534, 14, 0, 22, 21, 13),
(0.1431075384615385, 5, 4, 14, 7, 22),
(0.8675524260355031, 22, 6, 25, 22, 24),
(0.6105487218934911, 22, 15, 5, 3, 10),
(0.6017119526627219, 23, 25, 24, 2, 16),
(0.23021725443786975, 13, 21, 24, 24, 5),
(0.6308902248520711, 10, 23, 17, 17, 3),
(0.7687986982248523, 10, 0, 3, 22, 2),
(0.30283899408284026, 19, 4, 20, 15, 20),
(0.0753726982248521, 4, 11, 5, 10, 14),
(0.5991263668639054, 25, 22, 23, 19, 12),
(0.46613921893491117, 14, 12, 11, 8, 11),
(0.917547775147929, 8, 10, 4, 0, 13),
(0.5156906745562131, 18, 17, 23, 19, 0),
(0.8575289940828401, 21, 6, 13, 8, 13),
(0.5446086627218935, 7, 20, 21, 23, 22),
(0.6212901775147928, 12, 8, 23, 24, 6),
(0.8079170887573962, 21, 22, 15, 23, 17),
(0.5095875621301775, 14, 0, 18, 18, 16),
(0.8482301420118343, 9, 21, 18, 13, 21),
(0.5195814319526626, 24, 5, 11, 8, 19),
(0.6894559171597634, 2, 17, 3, 12, 15),
(0.1242453727810651, 11, 16, 22, 16, 5),
)

coeff = [[0 for j in range(26)] for i in goal]
res = [0. for j in goal]
for i, (target, a, b, c, x, y) in enumerate(goal):
    _x = sbox(x)/50 + (pixel_offset / 2)
    _y = sbox(y)/50 + (pixel_offset / 2)
    coeff[i][a] = 1 - _x - _y
    coeff[i][b] = _x
    coeff[i][c] =_y

    res[i] = target
temp_res = matrix(RR, coeff).solve_right(vector(RR, res))
print(temp_res)

temp = [Fraction(str(i)).limit_denominator() for i in temp_res]
temp = list(map(lambda x: inv_sbox(x*int(25)) / int(25), temp))

print(temp)

F, key = PolynomialRing(QQ, 24, 'k').objgens()

goal1 = (
(temp[0], key[12], key[2], key[17]),
(temp[1], key[2], key[20], key[7]),
(temp[2], key[7], key[5], key[8]),
(temp[3], key[0], key[5], key[16]),
(temp[4], key[12], key[8], key[11]),
(temp[5], key[4], key[13], key[9]),
(temp[6], key[14], key[3], key[12]),
(temp[7], key[9], key[15], key[8]),
(temp[8], key[3], key[7], key[2]),
(temp[9], key[13], key[2], key[7]),
(temp[10], key[5], key[6], key[21]),
(temp[11], key[8], key[21], key[9]),
(temp[12], key[19], key[12], key[3]),
(temp[13], key[10], key[3], key[23]),
(temp[14], key[4], key[11], key[16]),
(temp[15], key[18], key[1], key[8]),
(temp[16], key[14], key[19], key[5]),
(temp[17], key[6], key[4], key[18]),
(temp[18], key[7], key[9], key[14]),
(temp[19], key[6], key[4], key[7]),
(temp[20], key[2], key[23], key[17]),
(temp[21], key[7], key[19], key[12]),
(temp[22], key[23], key[11], key[20]),
(temp[23], key[12], key[8], key[18]),
(temp[24], key[12], key[9], key[21]),
(temp[25], key[19], key[8], key[22]),
)

brute_goal = (
(temp[0], 12, 2, 17),
(temp[1], 2, 20, 7),
(temp[2], 7, 5, 8),
(temp[3], 0, 5, 16),
(temp[4], 12, 8, 11),
(temp[5], 4, 13, 9),
(temp[6], 14, 3, 12),
(temp[7], 9, 15, 8),
(temp[8], 3, 7, 2),
(temp[9], 13, 2, 7),
(temp[10], 5, 6, 21),
(temp[11], 8, 21, 9),
(temp[12], 19, 12, 3),
(temp[13], 10, 3, 23),
(temp[14], 4, 11, 16),
(temp[15], 18, 1, 8),
(temp[16], 14, 19, 5),
(temp[17], 6, 4, 18),
(temp[18], 7, 9, 14),
(temp[19], 6, 4, 7),
(temp[20], 2, 23, 17),
(temp[21], 7, 19, 12),
(temp[22], 23, 11, 20),
(temp[23], 12, 8, 18),
(temp[24], 12, 9, 21),
(temp[25], 19, 8, 22),
)

keys = [set(range(25)) for i in range(24)]

# brute solution
for t, a, b, x in brute_goal:
    val = round(t.numerator / t.denominator, 9)
    indices = [((i//625)%25, (i//25)%25, i%25 ) for i, x in enumerate(mapping) if x == val]
    i, j, k = zip(*indices)
    keys[a] &= set(i)
    keys[b] &= set(j)
    keys[x] &= set(k)
    print(indices)
print(keys)

actual_key = [-1 for i in range(24)]
for j in range(30):
    for i, k in enumerate(keys):
        if len(k) == 1:
            actual_key[i] = list(k)[0]
            for l in range(24):
                keys[l] = keys[l] - k
            break
    else:
        break

print(actual_key)
print(list(map(inv_sbox, actual_key)))


exit(1)

eqs = []
for (k, a, b, x) in goal1:
    _x = x/25 + F(pixel_offset)
    print(f"lerp({a}, {b}, {x}) => {k}")
    eqs.append((a/25)*(1-_x)+(b/25)*(_x) - F(k.numerator)/k.denominator)

for eq in eqs:
    print(eq.coefficients())

print(eqs)
print(ideal(eqs).variety(proof=False))
basis = ideal(eqs).groebner_basis()
print(basis)
res = [0 for i in range(25)]
for i, var in enumerate(key):
    for k in range(25):
        if (var - k) in basis:
            res[i] = inv_sbox(k)

print(res)



