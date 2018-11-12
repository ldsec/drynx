import matplotlib.pyplot as plt
import pandas as pd

def addComma(v, index):
    v = v[:index] + ',' + v[index:]
    return v

raw_data = {
    'x_label': ['Baseline', '50% proofs', 'Single server\'s\nproofs', 'No proofs', 'Filt. Attr. in clear'],
    'y1_label': [49, 49, 49, 49, 0.04],             # Shuffling
    'y2_label': [688, 344, 229, 0, 0],              # Shuffling Proof
    'y3_label': [220, 110, 73, 0, 0],               # Shuffling Verif.
    'y4_label': [102, 102, 102, 102, 0.09],         # DDT
    'y5_label': [214, 107, 71, 0, 0],               # DDT Proof
    'y6_label': [171, 85, 57, 0, 0],                # DDT Verif.
    'y7_label': [0.01, 0.01, 0.01, 0.01, 0.01],     # Collective Aggr.
    'y8_label': [0.0004, 0.0002, 0.0001, 0, 0],     # Collective Aggr. Proof
    'y9_label': [0.4, 0.2, 0.13, 0, 0],             # Collective Aggr. Verif.
    'y10_label': [0.2, 0.2, 0.2, 0.2, 0.2],         # DRO
    'y11_label': [5.3, 2.6, 1.8, 0, 0],             # DRO Proof
    'y12_label': [1, 0.5, 0.3, 0, 0],               # DRO Verif.
    'y13_label': [0.03, 0.03, 0.03, 0.03, 0.03],    # Key Switching
    'y14_label': [0.02, 0.01, 0.006, 0, 0],         # Key Switching Proof
    'y15_label': [0.01, 0.005, 0.003, 0, 0],        # Key Switching Verif.
    'y_label': [1451, 800, 583, 151, 0.4]}

font = {'family': 'Bitstream Vera Sans',
        'size': 22}

plt.rc('font', **font)

df = pd.DataFrame(raw_data, raw_data['x_label'])

# Create the general plot and the "subplots" i.e. the bars
f, ax1 = plt.subplots(1, figsize=(14, 14))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_l = [i + 1 for i in range(len(df['y1_label']))]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [i + (bar_width / 2) for i in bar_l]

# Container of all bars
bars = []
# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y1_label data
                    df['y1_label'],
                    # set the width
                    width=bar_width,
                    label='Verif. Shuffle',
                    # with alpha 1
                    alpha=1,
                    # with color
                    color='#F4561D'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y2_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label on the bottom
                    bottom=df['y1_label'],
                    label='Verif. Shuffle Proof',
                    # with alpha 0.8
                    alpha=0.8,
                    # with color
                    hatch='////',
                    color='#F4561D'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y3_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label and y2_label on the bottom
                    bottom=[i + j for i, j in zip(df['y1_label'], df['y2_label'])],
                    label='Verif. Shuffle Proof Verif.',
                    # with alpha 0.6
                    alpha=0.5,
                    # with color
                    hatch='x',
                    color='#F4561D'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y4_label data
                    df['y4_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label on the bottom
                    bottom=[i + j + q for i, j, q in zip(df['y1_label'], df['y2_label'], df['y3_label'])],
                    label='Dist. Deterministic Tagging',
                    # with alpha 1
                    alpha=1,
                    # with color
                    color='#3232FF'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y5_label data
                    df['y5_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label on the bottom
                    bottom=[i + j + q + w for i, j, q, w in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'])],
                    label='Dist. Deterministic Tagging Proof',
                    # with alpha 0.8
                    alpha=0.8,
                    # with color
                    hatch='////',
                    color='#3232FF'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y6_label data
                    df['y6_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label on the bottom
                    bottom=[i + j + q + w + e for i, j, q, w, e in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'])],
                    label='Dist. Deterministic Tagging Proof Verif.',
                    # with alpha 0.6
                    alpha=0.5,
                    # with color
                    hatch='x',
                    color='#3232FF'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y7_label data
                    df['y7_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label on the bottom
                    bottom=[i + j + q + w + e + r for i, j, q, w, e, r in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                                df['y6_label'])],
                    label='Collective Aggr.',
                    # with alpha 1
                    alpha=1,
                    # with color
                    color='#8B4513'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y8_label data
                    df['y8_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label, y7_label on the bottom
                    bottom=[i + j + q + w + e + r + t for i, j, q, w, e, r, t in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                                df['y6_label'], df['y7_label'])],
                    label='Collective Aggr. Proof',
                    # with alpha 0.8
                    alpha=0.8,
                    # with color
                    hatch='////',
                    color='#8B4513'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y9_label data
                    df['y9_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label, y7_label, y8_label on the bottom
                    bottom=[i + j + q + w + e + r + t + z for i, j, q, w, e, r, t, z in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                                df['y6_label'], df['y7_label'], df['y8_label'])],
                    label='Collective Aggr. Proof Verif.',
                    # with alpha 0.6
                    alpha=0.5,
                    # with color
                    hatch='x',
                    color='#8B4513'))

#Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y10_label data
                    df['y10_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label, y7_label, y8_label,
                    # y9_label on the bottom
                    bottom=[i + j + q + w + e + r + t + z + u for i, j, q, w, e, r, t, z, u in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                                df['y6_label'], df['y7_label'], df['y8_label'], df['y9_label'])],
                    label='Dist. Results Obfuscation',
                    # with alpha 1
                    alpha=1,
                    # with color
                    color='#a4bf0d'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y11_label data
                    df['y11_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label, y7_label, y8_label, y9_label,
                    # y10_label on the bottom
                    # bottom=[i + j + q + w + e + r + t + z + u + i for i, j, q, w, e, r, t, z, u, i in
                    #        zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                    #            df['y6_label'], df['y7_label'], df['y8_label'], df['y9_label'], df['y10_label'])],
                    bottom=[i + j + q + w + e + r for i, j, q, w, e, r in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                                df['y6_label'])],
                    label='Dist. Results Obfuscation Proof',
                    # with alpha 0.8
                    alpha=0.8,
                    # with color
                    hatch='////',
                    color='#a4bf0d'))

# # Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y12_label data
                    df['y12_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label, y7_label, y8_label, y9_label,
                    # y10_label, y11_label on the bottom
                    # bottom=[i + j + q + w + e + r + t + z + u + i + o for i, j, q, w, e, r, t, z, u, i, o in
                    #        zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                    #            df['y6_label'], df['y7_label'], df['y8_label'], df['y9_label'], df['y10_label'],
                    #            df['y11_label'])],
                    bottom=[i + j + q + w + e + r + t for i, j, q, w, e, r, t in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                                df['y6_label'], df['y11_label'])],
                    label='Dist. Results Obfuscation Proof Verif.',
                    # with alpha 0.6
                    alpha=0.5,
                    # with color
                    hatch='x',
                    color='#a4bf0d'))

# # Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y13_label data
                    df['y13_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label, y7_label, y8_label, y9_label,
                    # y10_label, y11_label, y12_label on the bottom
                    # bottom=[i + j + q + w + e + r + t + z + u + i + o + b for i, j, q, w, e, r, t, z, u, i, o, b in
                    #        zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                    #            df['y6_label'], df['y7_label'], df['y8_label'], df['y9_label'], df['y10_label'],
                    #            df['y11_label'], df['y12_label'])],
                    bottom=[i + j + q + w + e + r + t + u for i, j, q, w, e, r, t, u in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                                df['y6_label'], df['y11_label'], df['y12_label'])],
                    label='Key Switch',
                    # with alpha 1
                    alpha=1,
                    # with color
                    color='#808080'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y14_label data
                    df['y14_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label, y7_label, y8_label, y9_label,
                    # y10_label, y11_label, y12_label, y13_label on the bottom
                    # bottom=[i + j + q + w + e + r + t + z + u + i + o + b + c for i, j, q, w, e, r, t, z, u,
                    #                                                              i, o, b, c in
                    #        zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                    #            df['y6_label'], df['y7_label'], df['y8_label'], df['y9_label'], df['y10_label'],
                    #            df['y11_label'], df['y12_label'], df['y13_label'])],
                    bottom=[i + j + q + w + e + r + t + u + p for i, j, q, w, e, r, t, u, p in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                                df['y6_label'], df['y11_label'], df['y12_label'], df['y13_label'])],
                    label='Key Switch Proof',
                    # with alpha 0.8
                    alpha=0.8,
                    # with color
                    hatch='////',
                    color='#808080'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y15_label data
                    df['y15_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label, y7_label, y8_label, y9_label,
                    # y10_label, y11_label, y12_label, y13_label, y14_label on the bottom
                    # bottom=[i + j + q + w + e + r + t + z + u + i + o + b + c + v for i, j, q, w, e, r, t, z, u,
                    #                                                              i, o, b, c, v in
                    #        zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                    #            df['y6_label'], df['y7_label'], df['y8_label'], df['y9_label'], df['y10_label'],
                    #            df['y11_label'], df['y12_label'], df['y13_label'], df['y14_label'])],
                    bottom=[i + j + q + w + e + r + t + u +p + v for i, j, q, w, e, r, t, u, p, v in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                                df['y6_label'], df['y11_label'], df['y12_label'], df['y13_label'], df['y14_label'])],
                    label='Key Switch Proof Verif.',
                    # with alpha 0.6
                    alpha=0.5,
                    # with color
                    hatch='x',
                    color='#808080'))

# Set the x ticks with names
plt.xticks(tick_pos, df['x_label'], rotation='15')
ax1.yaxis.grid(True)

# Labelling
height = [0, 0, 0, 0, 0, 0]
for rects in bars:
    i = 0
    for rect in rects:
        height[i] += rect.get_height()
        i += 1

ax1.text(tick_pos[0] - 0.24, height[0] + 10, addComma(str(int(df['y_label'][0])),1), color='black', fontweight='bold')
ax1.text(tick_pos[1] - 0.14, height[1] + 10, str(int(df['y_label'][1])), color='black', fontweight='bold')
ax1.text(tick_pos[2] - 0.14, height[2] + 10, str(int(df['y_label'][2])), color='black', fontweight='bold')
ax1.text(tick_pos[3] - 0.14, height[3] + 10, str(int(df['y_label'][3])), color='black', fontweight='bold')
ax1.text(tick_pos[4]-0.14,height[4]+10, str(df['y_label'][4]), color='black', fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=22)
plt.legend(loc='upper right', fontsize=21)

ax1.tick_params(axis='x', labelsize=24)
ax1.tick_params(axis='y', labelsize=24)

plt.ylim(0, 1600)

# Set a buffer around the edge
plt.xlim([min(tick_pos) - bar_width, max(tick_pos) + bar_width + 0.2])

plt.savefig('secure_census.pdf', format='pdf')
