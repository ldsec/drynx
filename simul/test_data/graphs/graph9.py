import matplotlib.pyplot as plt
import pandas as pd
import numpy

def addComma(v, index):
    v = v[:index] + ',' + v[index:]
    return v


font = {'family': 'Bitstream Vera Sans',
        'size': 18}

plt.rc('font', **font)

raw_data = {'x_label': ['12', '120', '1,2K', '12K', '120K', '1,2M'],  # Number responses
            'y1_label': [0.02, 0.02, 0.19, 1.8, 18.3, 189],  # Server transformation
            'y2_label': [0.02, 0.11, 0.67, 6.6, 71.7, 958],  # Server transformation -> proof creation
            'y3_label': [0.04, 0.11, 0.82, 6.9, 68.6, 643],}  # Server transformation -> proof verification


df = pd.DataFrame(raw_data, raw_data['x_label'])

# Create the general blog and the "subplots" i.e. the bars
f, ax1 = plt.subplots(1, figsize=(9, 7))

# Set the bar width
bar_width = 0.6

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
                    label='Server Transformation',
                    # with alpha 0.6
                    alpha=0.5,
                    # with color
                    color='#3F62AD'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y2_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label on the bottom
                    bottom=df['y1_label'],
                    label='Proof Creation',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#4C8E8B'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y3_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label on the bottom
                    bottom=[i + j for i, j in zip(df['y1_label'], df['y2_label'])],
                    label='Proof Verif.',
                    # with alpha 0.6
                    alpha=0.5,
                    # with color
                    color='#A747B8'))

x = numpy.array([12, 120, 1200, 12000, 120000, 1200000])
y = 0.00148996 * x + 0
x1 = numpy.array([1.25, 2.25, 3.25, 4.25, 5.25, 6.25])
ax1.plot(x1, y, linestyle='--', color='red', label="Trendline")

# Set the x ticks with names
plt.xticks(tick_pos, df['x_label'])
ax1.set_yscale('log')
ax1.yaxis.grid(True)

# Labelling
height = [0, 0, 0, 0, 0, 0]
for rects in bars:
    i = 0
    for rect in rects:
        height[i] += rect.get_height()
        i += 1

ax1.text(tick_pos[0] - 0.28, 0.011, str(df['y1_label'][0]), color='black', fontweight='bold')
ax1.text(tick_pos[1] - 0.28, 0.012, str(df['y1_label'][1]), color='black', fontweight='bold')
ax1.text(tick_pos[2] - 0.28, 0.05, str(df['y1_label'][2]), color='black', fontweight='bold')
ax1.text(tick_pos[3] - 0.20, 0.1, str(df['y1_label'][3]), color='black', fontweight='bold')
ax1.text(tick_pos[4] - 0.28, 0.2, str(df['y1_label'][4]), color='black', fontweight='bold')
ax1.text(tick_pos[5] - 0.24, 0.4, str(int(df['y1_label'][5])), color='black', fontweight='bold')

ax1.text(tick_pos[0] - 0.28, height[0] - height[0] / 1.4, str(df['y2_label'][0]), color='black', fontweight='bold')
ax1.text(tick_pos[1] - 0.28, height[1] - height[1] / 1.3, str(df['y2_label'][1]), color='black', fontweight='bold')
ax1.text(tick_pos[2] - 0.28, height[2] - height[2] / 1.3, str(df['y2_label'][2]), color='black', fontweight='bold')
ax1.text(tick_pos[3] - 0.20, height[3] - height[3] / 1.3, str(df['y2_label'][3]), color='black', fontweight='bold')
ax1.text(tick_pos[4] - 0.28, height[4] - height[4] / 1.3, str(df['y2_label'][4]), color='black', fontweight='bold')
ax1.text(tick_pos[5] - 0.24, height[5] - height[5] / 1.3, str(int(df['y2_label'][5])), color='black', fontweight='bold')

ax1.text(tick_pos[0] - 0.28, height[0] + height[0] / 8, str(df['y3_label'][0]), color='#A747B8', fontweight='bold')
ax1.text(tick_pos[1] - 0.28, height[1] + height[1] / 8, str(df['y3_label'][1]), color='#A747B8', fontweight='bold')
ax1.text(tick_pos[2] - 0.28, height[2] + height[2] / 8, str(df['y3_label'][2]), color='#A747B8', fontweight='bold')
ax1.text(tick_pos[3] - 0.20, height[3] + height[3] / 8, str(df['y3_label'][3]), color='#A747B8', fontweight='bold')
ax1.text(tick_pos[4] - 0.28, height[4] + height[4] / 8, str(df['y3_label'][4]), color='#A747B8', fontweight='bold')
ax1.text(tick_pos[5] - 0.24, height[5] + height[5] / 8, str(int(df['y3_label'][5])), color='#A747B8', fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=22)
ax1.yaxis.set_label_coords(-0.11, 0.5)
ax1.set_xlabel("Total number of ciphertexts", fontsize=22)
plt.legend(loc='upper left')

ax1.tick_params(axis='x', labelsize=22)
ax1.tick_params(axis='y', labelsize=22)

labels = [item.get_text() for item in ax1.get_yticklabels()]
labels[0] = '0'
labels[1] = '0.01'
labels[2] = '0.1'
labels[3] = '1'
labels[4] = '10'
labels[5] = '100'
labels[6] = '1K'
labels[7] = '10K'
ax1.set_yticklabels(labels)

# Set a buffer around the edge
plt.xlim([min(tick_pos) - bar_width, max(tick_pos) + bar_width + 0.2])

plt.savefig('dynamic_cothority.pdf', format='pdf')

