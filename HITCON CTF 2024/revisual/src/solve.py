def lerp(a, b, x):
    # print(a, int(a + (b - a) * x), b)
    return round(a + (b - a) * x, 5)


def lerp3(a, b, c, x, y):
    # print(a, b, c, x, y)
    res = (1 - x - y) * a + x * b + y * c
    return round(res, 5)


pixel_offset = 1 / 650 / 2
multi = 1 / 25
mapping = [0 for i in range(25**3)]
for i in range(25):
    for j in range(25):
        for k in range(25):
            mapping[i * 625 + j * 25 + k] = lerp(
                i * multi, j * multi, k / 25 + pixel_offset
            )

print(len(mapping))
print(len(set(mapping)))
# [19, 9, 8, 15, 3, 18, 17, 10, 23, 5, 0, 6, 24, 14, 12, 11, 2, 13, 16, 4, 7, 1, 21, 22]
target = [
    0.63169,
    0.25403,
    0.42218,
    0.15185,
    0.76769,
    0.25252,
    0.50523,
    0.74462,
    0.56538,
    0.08948,
    0.22114,
    0.70495,
]
for t in target:
    print(t)
    indices = [
        (i // 625, (i // 25) % 25, i % 25) for i, x in enumerate(mapping) if x == t
    ]
    print(indices)
