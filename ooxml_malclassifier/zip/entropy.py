import math


def entropy(data):
    size = len(data)

    freqList = [0] * 256
    for b in data:
        freqList[b] += 1

    ent = 0.0
    for f in freqList:
        if f > 0:
            freq = float(f) / size
            ent = ent + freq * math.log(freq, 2)
    ent = -ent
    return ent