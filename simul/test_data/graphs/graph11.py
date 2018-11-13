import matplotlib.pyplot as plt
import pandas as pd

font = {'family': 'Bitstream Vera Sans',
        'size': 18}

plt.rc('font', **font)

raw_data = {'x_label': ['10ms', '50ms', '100ms', '200ms'],              # Number responses
            'y1_label': [8.2-1.3, 20.6-1.7, 38-1.5, 77.1-1.3],          # Communication 80ms
            'y2_label': [1.3, 1.7, 1.5, 1.3],                           # Computation 80ms
            'y3_label': [15-1.6, 25.7-1.3, 39.1-1.3, 79.5-1.4],         # Communication 40ms
            'y4_label': [1.6, 1.3, 1.3, 1.4],                           # Computation 40ms
            'y5_label': [23.7-1.2, 33.2-1.3, 51.1-1.3, 85.8-1.3],       # Communication 20ms
            'y6_label': [1.2, 1.3, 1.3, 1.3],                           # Computation 20ms
            'empty': [0, 0, 0, 0],                                      # empty
            'y2text_label': [8.2, 20.6, 38, 77.1],
            'y4text_label': [15, 25.7, 39.1, 79.5],
            'y6text_label': [23.7, 33.2, 51.1, 85.8]}

df = pd.DataFrame(raw_data, raw_data['x_label'])

# Create the general plot and the "subplots" i.e. the bars
f, ax1 = plt.subplots(1, figsize=(10, 8))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_l2 = [1, 3.7, 6.4, 9.1]
bar_l4 = [1.6, 4.3, 7, 9.7]
bar_l6 = [2.2, 4.9, 7.6, 10.3]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [i + (bar_width / 2) for i in bar_l4]

# Container of all bars
bars = []

# 80ms
# Create a bar plot, in position bar_l2
bars.append(ax1.bar(bar_l2,
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

# Create a bar plot, in position bar_l2
bars.append(ax1.bar(bar_l2,
                    # using the y1_label data
                    df['y1_label'],
                    # set the width
                    width=bar_width,
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='#3232FF'))

# Create a bar plot, in position bar_l2
bars.append(ax1.bar(bar_l2,
                    # using the y2_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    label='80Mbps',
                    # with y1_label on the bottom
                    bottom=df['y1_label'],
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#3232FF'))

# 40ms
# Create a bar plot, in position bar_l4
bars.append(ax1.bar(bar_l4,
                    # using the y3_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='#a4bf0d'))

# Create a bar plot, in position bar_l4
bars.append(ax1.bar(bar_l4,
                    # using the y4_label data
                    df['y4_label'],
                    # set the width
                    width=bar_width,
                    label='40Mbps',
                    # with y3_label on the bottom
                    bottom=df['y3_label'],
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#a4bf0d'))


# 20ms
# Create a bar plot, in position bar_l6
bars.append(ax1.bar(bar_l6,
                    # using the y5_label data
                    df['y5_label'],
                    # set the width
                    width=bar_width,
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='#F4561D'))

# Create a bar plot, in position bar_l6
bars.append(ax1.bar(bar_l6,
                    # using the y6_label data
                    df['y6_label'],
                    # set the width
                    width=bar_width,
                    label='20Mbps',
                    # with y5_label on the bottom
                    bottom=df['y5_label'],
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#F4561D'))


# Set the x ticks with names
plt.xticks(tick_pos, df['x_label'])
ax1.yaxis.grid(True)

ax1.text(bar_l2[0]-0.03, df['y2text_label'][0]+1, str(df['y2text_label'][0]), color='#3232FF', fontweight='bold',
         fontsize=16)
ax1.text(bar_l2[1]-0.28, df['y2text_label'][1]+1, str(df['y2text_label'][1]), color='#3232FF', fontweight='bold',
         fontsize=16)
ax1.text(bar_l2[2], df['y2text_label'][2]+1, str(int(df['y2text_label'][2])), color='#3232FF', fontweight='bold',
         fontsize=16)
ax1.text(bar_l2[3]-0.28, df['y2text_label'][3]+1, str(df['y2text_label'][3]), color='#3232FF', fontweight='bold',
         fontsize=16)


ax1.text(bar_l4[0], df['y4text_label'][0]+1, str(int(df['y4text_label'][0])), color='#a4bf0d', fontweight='bold',
         fontsize=16)
ax1.text(bar_l4[1]-0.28, df['y4text_label'][1]+1, str(df['y4text_label'][1]), color='#a4bf0d', fontweight='bold',
         fontsize=16)
ax1.text(bar_l4[2]-0.28, df['y4text_label'][2]+3.6, str(df['y4text_label'][2]), color='#a4bf0d', fontweight='bold',
         fontsize=16)
ax1.text(bar_l4[3]-0.28, df['y4text_label'][3]+2.8, str(df['y4text_label'][3]), color='#a4bf0d', fontweight='bold',
         fontsize=16)

ax1.text(bar_l6[0], df['y6text_label'][0]+1, str(int(df['y6text_label'][0])), color='#F4561D', fontweight='bold',
         fontsize=16)
ax1.text(bar_l6[1]-0.28, df['y6text_label'][1]+1, str(df['y6text_label'][1]), color='#F4561D', fontweight='bold',
         fontsize=16)
ax1.text(bar_l6[2]-0.28, df['y6text_label'][2]+1, str(df['y6text_label'][2]), color='#F4561D', fontweight='bold',
         fontsize=16)
ax1.text(bar_l6[3]-0.28, df['y6text_label'][3]+1, str(df['y6text_label'][3]), color='#F4561D', fontweight='bold',
         fontsize=16)

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=22)
ax1.set_xlabel("Latency", fontsize=22)
plt.legend(loc='upper left')

ax1.tick_params(axis='x', labelsize=22)
ax1.tick_params(axis='y', labelsize=22)

# Set a buffer around the edge
plt.xlim([min(tick_pos) - bar_width - 0.6, max(tick_pos) + bar_width + 0.6])

plt.savefig('vary_bandwith.pdf', format='pdf')
