import matplotlib.pyplot as plt
import pandas as pd

raw_data = {'x_label': ['3', '4', '5', '6', '7'],                                           # Number of servers
            'y1_label': [8.4-1.1, 9.6-1.4, 10-1.4, 10.7-1.5, 11.8-2],                       # Communication
            'y2_label': [1.12, 1.4, 1.4, 1.5, 2],                                           # Shuffle+DDT
            'y3_label': [0.016-0.001, 0.022-0.001, 0.04-0.002, 0.04-0.002, 0.04-0.002],     # Communication
            'y4_label': [0.001, 0.001, 0.002, 0.002, 0.002],                                # Collective Aggregation
            'y5_label': [0.18-0.01, 0.24-0.01, 0.3-0.01, 0.36-0.01, 0.43-0.01],             # Communication
            'y6_label': [0.01, 0.01, 0.01, 0.01, 0.01],                                     # DiffPri
            'y7_label': [0.09-0.06, 0.1-0.06, 0.14-0.09, 0.18-0.1, 0.2-0.1],                # Communication
            'y8_label': [0.06, 0.06, 0.09, 0.1, 0.1],                                       # Key Switch
            'empty': [0, 0, 0, 0, 0],                                                       # empty
            'y2text_label': [8.4, 9.6, 10, 10.7, 11.8],
            'y4text_label': [0.02, 0.02, 0.04, 0.04, 0.04],
            'y6text_label': [0.2, 0.24, 0.3, 0.36, 0.43],
            'y8text_label': [0.09, 0.1, 0.14, 0.18, 0.2]}

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
                    # using the empty data
                    df['empty'],
                    # set the width
                    width=bar_width,
                    label='Communication',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='white'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y1_label data
                    df['y1_label'],
                    # set the width
                    width=bar_width,
                    # with alpha 0.6
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='#F4561D'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y2_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label on the bottom
                    bottom=df['y1_label'],
                    label='Verif. Shuffle + DDT',
                    # with alpha 0.6
                    alpha=0.5,
                    ecolor='black',
                    # with color
                    color='#F4561D'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y3_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label on the bottom
                    bottom=[i + j for i, j in zip(df['y1_label'], df['y2_label'])],
                    # with alpha 0.7
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='#654321'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y4_label data
                    df['y4_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label on the bottom
                    bottom=[i + j + z for i, j, z in zip(df['y1_label'], df['y2_label'], df['y3_label'])],
                    label='Collective Aggr.',
                    # with alpha 0.7
                    alpha=0.5,
                    # with color
                    color='#654321'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y5_label data
                    df['y5_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label on the bottom
                    bottom=[i + j + z + k for i, j, z, k in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'])],
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='#a4bf0d'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y6_label data
                    df['y6_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label on the bottom
                    bottom=[i + j + z + k + l for i, j, z, k, l in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'])],
                    label='DRO',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#a4bf0d'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y5_label data
                    df['y7_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label and y6_label on the bottom
                    bottom=[i + j + z + k + l + o for i, j, z, k, l, o in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                                df['y6_label'])],
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='#808080'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y6_label data
                    df['y8_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label on the bottom
                    bottom=[i + j + z + k + l + o + t for i, j, z, k, l, o, t in
                            zip(df['y1_label'], df['y2_label'], df['y3_label'], df['y4_label'], df['y5_label'],
                                df['y6_label'], df['y7_label'])],
                    label='Key Switch',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#808080'))

# Set the x ticks with names
plt.xticks(tick_pos, df['x_label'])
ax1.yaxis.grid(True)

# Labelling
height = [0, 0, 0, 0, 0, 0]
for rects in bars:
    i = 0
    for rect in rects:
        height[i] += rect.get_height()
        i += 1

ax1.text(tick_pos[0] - 0.15, height[0] - height[0] / 2, str(df['y2text_label'][0]), color='black', fontweight='bold')
ax1.text(tick_pos[1] - 0.15, height[1] - height[1] / 2, str(df['y2text_label'][1]), color='black', fontweight='bold')
ax1.text(tick_pos[2] - 0.23, height[2] - height[2] / 2, str(df['y2text_label'][2]), color='black', fontweight='bold')
ax1.text(tick_pos[3] - 0.23, height[3] - height[3] / 2, str(df['y2text_label'][3]), color='black', fontweight='bold')
ax1.text(tick_pos[4] - 0.12, height[4] - height[4] / 2, str(int(df['y2text_label'][4])), color='black', fontweight='bold')

ax1.text(tick_pos[0] + 0.26, height[0] - height[0] / 8, str(df['y4text_label'][0]), color='#654321', fontweight='bold')
ax1.text(tick_pos[1] + 0.26, height[1] - height[1] / 8, str(df['y4text_label'][1]), color='#654321', fontweight='bold')
ax1.text(tick_pos[2] + 0.26, height[2] - height[2] / 8, str(df['y4text_label'][2]), color='#654321', fontweight='bold')
ax1.text(tick_pos[3] + 0.26, height[3] - height[3] / 8, str(df['y4text_label'][3]), color='#654321', fontweight='bold')
ax1.text(tick_pos[4] + 0.26, height[4] - height[4] / 8, str(df['y4text_label'][4]), color='#654321', fontweight='bold')

ax1.text(tick_pos[0] + 0.26, height[0], str(df['y6text_label'][0]), color='#a4bf0d', fontweight='bold')
ax1.text(tick_pos[1] + 0.26, height[1], str(df['y6text_label'][1]), color='#a4bf0d', fontweight='bold')
ax1.text(tick_pos[2] + 0.26, height[2], str(df['y6text_label'][2]), color='#a4bf0d', fontweight='bold')
ax1.text(tick_pos[3] + 0.26, height[3], str(df['y6text_label'][3]), color='#a4bf0d', fontweight='bold')
ax1.text(tick_pos[4] + 0.26, height[4], str(df['y6text_label'][4]), color='#a4bf0d', fontweight='bold')

ax1.text(tick_pos[0] - 0.23, height[0] + height[0] / 20, str(df['y8text_label'][0]), color='#808080', fontweight='bold')
ax1.text(tick_pos[1] - 0.15, height[1] + height[1] / 20, str(df['y8text_label'][1]), color='#808080', fontweight='bold')
ax1.text(tick_pos[2] - 0.23, height[2] + height[2] / 20, str(df['y8text_label'][2]), color='#808080', fontweight='bold')
ax1.text(tick_pos[3] - 0.23, height[3] + height[3] / 20, str(df['y8text_label'][3]), color='#808080', fontweight='bold')
ax1.text(tick_pos[4] - 0.15, height[4] + height[4] / 20, str(df['y8text_label'][4]), color='#808080', fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=22)
ax1.set_xlabel("Number of servers in the collective authority", fontsize=22)
plt.legend(loc=1, fontsize=18)

ax1.tick_params(axis='x', labelsize=22)
ax1.tick_params(axis='y', labelsize=22)

# Set a buffer around the edge
plt.xlim([min(tick_pos) - bar_width, max(tick_pos) + bar_width + 0.3])
plt.ylim([0, 25])

plt.savefig('vary_num_servers.pdf', format='pdf')
