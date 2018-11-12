import matplotlib.pyplot as plt
import pandas as pd

raw_data = {'x_label': ['10', '20', '100', '1K'],                       # Number groups
            'y1_label': [0.04, 0.05, 0.09, 0.5],                        # Collective Aggregation Verification
            'y2_label': [5.5-0.2, 5.5-0.2, 5.5-0.2, 5.5-0.2],           # DRO Proofs
            'y3_label': [1, 1, 1, 1],                                   # DRO Verification
            'y4_label': [0.14-0.09, 0.2-0.11, 0.6-0.4, 4.8-2.7],        # Key Switch Proofs
            'y5_label': [0.05, 0.05, 0.13, 0.9],                        # Key Switch Verification
            }

font = {'family': 'Bitstream Vera Sans',
        'size': 18}

plt.rc('font', **font)

df = pd.DataFrame(raw_data, raw_data['x_label'])

# Create the general plot and the "subplots" i.e. the bars
f, ax1 = plt.subplots(1, figsize=(9, 7))

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
                    label='Collective Aggr. Proof Verif.',
                    # with alpha 0.7
                    alpha=0.5,
                    # with color
                    color='#8B4513'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y1_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label on the bottom
                    bottom=df['y1_label'],
                    label='DRO Proof',
                    # with alpha 0.7
                    alpha=0.5,
                    # with color
                    color='#a4bf0d'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y1_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label and y4_label on the bottom
                    bottom=[i + j for i, j in zip(df['y1_label'], df['y2_label'])],
                    label='DRO Proof Verif.',
                    # with alpha 0.7
                    alpha=0.5,
                    # with color
                    color='#2C6638'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y2_label data
                    df['y4_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label and y3_label on the bottom
                    bottom=[i + j + k for i, j, k in zip(df['y1_label'], df['y2_label'], df['y3_label'])],
                    label='Key Switch Proof',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#808080'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y3_label data
                    df['y5_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label and y4_label on the bottom
                    bottom=[i + j + k + o for i, j, k, o in zip(df['y1_label'], df['y2_label'], df['y3_label'],
                                                         df['y4_label'])],
                    label='Key Switch Proof Verif.',
                    # with alpha 0.6
                    alpha=0.5,
                    # with color
                    color='#040505'))

# Set the x ticks with names
plt.xticks(tick_pos, df['x_label'])
ax1.yaxis.grid(True)

# Labelling
height = [0, 0, 0, 0, 0]
for rects in bars:
    i = 0
    for rect in rects:
        height[i] += rect.get_height()
        i += 1


ax1.text(tick_pos[0] + 0.27, 0.2, str(df['y1_label'][0]), color='#8B4513', fontweight='bold')
ax1.text(tick_pos[1] + 0.27, 0.2, str(df['y1_label'][1]), color='#8B4513', fontweight='bold')
ax1.text(tick_pos[2] + 0.27, 0.2, str(df['y1_label'][2]), color='#8B4513', fontweight='bold')
ax1.text(tick_pos[3] + 0.27, 0.2, str(df['y1_label'][3]), color='#8B4513', fontweight='bold')

ax1.text(tick_pos[0] - 0.13, height[0] - height[0] / 2, str(df['y2_label'][0]), color='black', fontweight='bold')
ax1.text(tick_pos[1] - 0.13, height[1] - height[1] / 2, str(df['y2_label'][1]), color='black', fontweight='bold')
ax1.text(tick_pos[2] - 0.13, height[2] - height[2] / 2, str(df['y2_label'][2]), color='black', fontweight='bold')
ax1.text(tick_pos[3] - 0.13, height[3] - height[3] / 1.7, str(df['y2_label'][3]), color='black', fontweight='bold')

ax1.text(tick_pos[0] - 0.05, height[0] - height[0] / 7, str(df['y3_label'][0]), color='black', fontweight='bold')
ax1.text(tick_pos[1] - 0.05, height[1] - height[1] / 7, str(df['y3_label'][1]), color='black', fontweight='bold')
ax1.text(tick_pos[2] - 0.05, height[2] - height[2] / 6, str(df['y3_label'][2]), color='black', fontweight='bold')
ax1.text(tick_pos[3] - 0.05, height[3] - height[3] / 2.6, str(df['y3_label'][3]), color='black', fontweight='bold')


ax1.text(tick_pos[0] + 0.27, height[0] - height[0] / 11, str(df['y4_label'][0]), color='#808080', fontweight='bold')
ax1.text(tick_pos[1] + 0.27, height[1] - height[1] / 11, str(df['y4_label'][1]), color='#808080', fontweight='bold')
ax1.text(tick_pos[2] + 0.27, height[2] - height[2] / 11, str(df['y4_label'][2]), color='#808080', fontweight='bold')
ax1.text(tick_pos[3] + 0.27, height[3] - height[3] / 4, str(df['y4_label'][3]), color='#808080', fontweight='bold')

ax1.text(tick_pos[0] - 0.17, height[0] + height[0] / 30, str(df['y5_label'][0]), color='#3d3939', fontweight='bold')
ax1.text(tick_pos[1] - 0.17, height[1] + height[1] / 30, str(df['y5_label'][1]), color='#3d3939', fontweight='bold')
ax1.text(tick_pos[2] - 0.17, height[2] + height[2] / 30, str(df['y5_label'][2]), color='#3d3939', fontweight='bold')
ax1.text(tick_pos[3] - 0.13, height[3] + height[3] / 30, str(df['y5_label'][3]), color='#3d3939', fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=22)
ax1.set_xlabel("Number of groups", fontsize=22)
plt.legend(loc='upper left', fontsize=21)

labels = [item.get_text() for item in ax1.get_yticklabels()]

ax1.tick_params(axis='x', labelsize=22)
ax1.tick_params(axis='y', labelsize=22)

plt.ylim(0, 15)

# Set a buffer around the edge
plt.xlim([min(tick_pos) - bar_width, max(tick_pos) + bar_width + 0.2])

plt.savefig('proof_vary_num_groups.pdf', format='pdf')
