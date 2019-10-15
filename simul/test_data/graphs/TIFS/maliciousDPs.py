import matplotlib.pyplot as plt
import numpy as np
import random
import math


def cosine_similarity(a_1, b_1, a_2, b_2):
    n = len(a_1)
    numerator = 0.0
    denominator_a = 0.0
    denominator_b = 0.0
    for i in range(n):
        numerator += a_1[i] * b_1[i]
        denominator_a += a_2[i] * a_2[i]
        denominator_b += b_2[i] * b_2[i]

    denominator = math.sqrt(denominator_a) * math.sqrt(denominator_b)
    return numerator / denominator


font = {'family': 'Bitstream Vera Sans',
        'size': 17}

plt.rc('font', **font)

totalNbrDPs = 8922

x = np.linspace(0, 10, num=100)

d = totalNbrDPs * x / 100  # maliciousDPs
h = totalNbrDPs * (100 - x) / 100  # honestDPs
ah = 70
e = 100
c = 0

# Create the general plot and the "subplots"
f, ax = plt.subplots(1, figsize=(9, 7))

am = (h * ah + d * e) / (h + c)
y = np.absolute(1 - (am / ah)) * 100
ax.plot(x, y, label='avg - range: [40,100]', linestyle="--")

e = 256
am = (h * ah + d * e) / (h + c)
y = np.absolute(1 - (am / ah)) * 100
ax.plot(x, y, label='avg - range: [0,256]')

# Plot cosine part
# A140100 = [random.randrange(40, 100) for i in range(1000)]
A140100 = [70 for i in range(1000)]
A240100 = A140100.copy()
# B140100 = [random.randrange(40, 100) for i in range(1000)]
B140100 = [70 for i in range(1000)]
B240100 = B140100.copy()

realVal40100 = cosine_similarity(A140100, B140100, A240100, B240100)
error40100 = []

# A10256 = [random.randrange(0, 256) for j in range(1000)]
A10256 = [70 for j in range(1000)]
A20256 = A10256.copy()
# B10256 = [random.randrange(0, 256) for j in range(1000)]
B10256 = [70 for j in range(1000)]
B20256 = B10256.copy()

realVal0256 = cosine_similarity(A10256, B10256, A20256, B20256)
error0256 = []

for i in range(0, 11):
    if i != 0:
        # 40-100
        A140100[i] = 100
        A240100[i] = 40
        B140100[i] = 100
        B240100[i] = 40

        # 0-256
        A10256[i] = 256
        A20256[i] = 0
        B10256[i] = 256
        B20256[i] = 0

    val = cosine_similarity(A140100, B140100, A240100, B240100)
    error40100.append(abs(1 - val)*100)

    val = cosine_similarity(A10256, B10256, A20256, B20256)
    error0256.append(abs(1 - val)*100)

x1 = [i for i in range(11)]
ax.plot(x1, error40100, label='cosim - range: [40,100]', linestyle="--")
x1[0] = 0.1
ax.plot(x1, error0256, label='cosim - range: [0,256]')

ax.set_xscale("log")

# Set the label and legends
ax.set_xlabel("Percentage of malicious DPs (%)", fontsize=20)
ax.set_ylabel("Relative Error (%)", fontsize=20)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

ax.grid()
ax.legend()

plt.ylim(bottom=0, top=50)
plt.xlim(right=10)

labels = [item.get_text() for item in ax.get_xticklabels()]
labels[1] = '0'
labels[2] = '0.1'
labels[3] = '1'
labels[4] = '10'
ax.set_xticklabels(labels)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

plt.savefig('maliciousDPs.pdf', bbox_inches='tight', pad_inches=0)
