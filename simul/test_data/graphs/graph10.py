import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

raw_data = {
    'x_label': ['300', '3K', '30K', '300K'],
    'y1_label': [0.07, 0.6, 2.7, 25.3],  # DDT (Aggr.)
    'y2_label': [0.06, 0.5, 2.4, 23.5],  # DDT (Shuffl.)
    'y3_label': [0.18, 2.1, 13, 190],  # DDT Proof (Aggr.)
    'y4_label': [0.19, 1.4, 12.5, 175],  # DDT Proof (Shuffl.)
    'empty': [0, 0, 0, 0]  # empty
}

font = {'family': 'Bitstream Vera Sans',
        'size': 24}

plt.rc('font', **font)

df = pd.DataFrame(raw_data, raw_data['x_label'])

N = 4
ind = np.arange(N)  # The x locations for the groups

# Create the general blog and the "subplots" i.e. the bars
fig, ax1 = plt.subplots(1, figsize=(14, 12))

# Set the bar width
bar_width = 0.35

# Container of all bars
bars = []

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind,
                    # using the y1_label data
                    df['y1_label'],
                    # set the width
                    width=bar_width,
                    label='DDT (Aggr.)',
                    # with alpha 1
                    alpha=1,
                    # with color
                    color='#3232FF'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind,
                    # using the y3_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label on the bottom
                    bottom=df['y1_label'],
                    # with alpha 0.8
                    alpha=0.8,
                    # with color
                    hatch='////',
                    color='#3232FF'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                    # using the y2_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    label='DDT (Shuffl.)',
                    # with alpha 1
                    alpha=1,
                    # with color
                    color='#6495ED'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                    # using the y4_label data
                    df['y4_label'],
                    # set the width
                    width=bar_width,
                    # with y2_label on the bottom
                    bottom=df['y2_label'],
                    # with alpha 0.8
                    alpha=0.8,
                    # with color
                    hatch='////',
                    color='#6495ED'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind,
                    # using the empty data
                    df['empty'],
                    # set the width
                    width=bar_width,
                    # with the label post score
                    label='Proofs',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='white'))

# Set the x ticks with names
ax1.set_xticks(ind + bar_width)
ax1.set_xticklabels(df['x_label'])
ax1.set_yscale('log')
ax1.yaxis.grid(True)

# Labelling
height = [0, 0, 0, 0, 0, 0, 0, 0]
for rects in bars:
    i = 0
    for rect in rects:
        height[i] += rect.get_height()
        i += 1

ax1.text(ind[0] + 0.03, height[0] / 15, str(df['y1_label'][0]), color='black', fontweight='bold')
ax1.text(ind[1] + 0.07, height[1] / 30, str(df['y1_label'][1]), color='black', fontweight='bold')
ax1.text(ind[2] + 0.07, height[2] / 60, str(df['y1_label'][2]), color='black', fontweight='bold')
ax1.text(ind[3] + 0.03, height[3] / 100, str(df['y1_label'][3]), color='black', fontweight='bold')

ax1.text(ind[0] + bar_width + 0.03, height[0] / 25, str(df['y2_label'][0]), color='black', fontweight='bold')
ax1.text(ind[1] + bar_width + 0.07, height[1] / 50, str(df['y2_label'][1]), color='black', fontweight='bold')
ax1.text(ind[2] + bar_width + 0.07, height[2] / 80, str(df['y2_label'][2]), color='black', fontweight='bold')
ax1.text(ind[3] + bar_width + 0.03, height[3] / 150, str(df['y2_label'][3]), color='black', fontweight='bold')

ax1.text(ind[0] + 0.03, height[0] / 3 - height[0] / 10, str(df['y3_label'][0]), color='black', fontweight='bold')
ax1.text(ind[1] + 0.07, height[1] / 3 - height[1] / 10, str(df['y3_label'][1]), color='black', fontweight='bold')
ax1.text(ind[2] + 0.08, height[2] / 3 - height[2] / 10, str(int(df['y3_label'][2])), color='black', fontweight='bold')
ax1.text(ind[3] + 0.04, height[3] / 3 - height[3] / 10, str(int(df['y3_label'][3])), color='black', fontweight='bold')

ax1.text(ind[0] + bar_width + 0.03, height[0] / 5, str(df['y4_label'][0]), color='black', fontweight='bold')
ax1.text(ind[1] + bar_width + 0.07, height[1] / 5, str(df['y4_label'][1]), color='black', fontweight='bold')
ax1.text(ind[2] + bar_width + 0.08, height[2] / 5, str(int(df['y4_label'][2])), color='black', fontweight='bold')
ax1.text(ind[3] + bar_width + 0.04, height[3] / 5, str(int(df['y4_label'][3])), color='black', fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=24)
ax1.set_xlabel("Total number of patients", fontsize=24)
plt.legend(loc='upper left')

ax1.tick_params(axis='x', labelsize=24)
ax1.tick_params(axis='y', labelsize=24)

plt.savefig('unlynx_i2b2.pdf', format='pdf')
