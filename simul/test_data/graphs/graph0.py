import matplotlib.pyplot as plt
import pandas as pd
import pylab as pyl

font = {'family': 'Bitstream Vera Sans',
        'size': 16}

plt.rc('font', **font)

raw_data = {'h_label': ['S1', 'S2', 'S3'],                                          # Servers
            'y1_label': [4.6-0.09, 5.1-0.22, 4.8-0.24],                             # Communication (Verif. Shuffle)
            'y2_label': [0.09, 0.22, 0.24],                                         # Verif. Shuffle
            'y3_label': [2.6-0.9, 3.3-0.91, 2.9-0.9],                               # Communication (DDT)
            'y4_label': [0.9, 0.91, 0.9],                                           # DDT
            'waiting': [8.4-4.6-2.6, 8.4-5.1-3.3, 8.4-4.8-2.9],                     # time waiting
            'y5_label': [0.016-0.015, 0.016-0.015, 0.016-0.015],                    # Communication (Collective Aggr.)
            'y6_label': [0.015, 0.015, 0.015],                                      # Collective Aggr.
            'y7_label': [0.18-0.01, 0.18-0.01, 0.18-0.01],                          # Communication (DRO)
            'y8_label': [0.01, 0.01, 0.01],                                         # DRO
            'y9_label': [0.09-0.019, 0.09-0.02, 0.09-0.02],                         # Communication (Key Switch)
            'y10_label': [0.019, 0.02, 0.02],                                       # Key Switch
            'empty': [0, 0, 0]                                                      # empty
}

df = pd.DataFrame(raw_data, raw_data['h_label'])

# Create the general plot and the "subplots" i.e. the bars
f, ax1 = plt.subplots(1, figsize=(9, 7))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_l = pos = pyl.arange(len(df['h_label']))+.3

# Positions of the y-axis ticks (center of the bars as bar labels)
tick_pos = [i + (bar_width / 2) for i in bar_l]

# Container of all bars
bars = []

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                    # using the empty data
                    df['empty'],
                    bar_width,
                    label='Communication',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='white'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                    # using the empty data
                    df['y1_label'],
                    bar_width,
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='#F4561D'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y2_label'],
                     bar_width,
                     # with y1_label on the left
                     left=df['y1_label'],
                     label='Verif. Shuffle',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     color='#F4561D'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y3_label'],
                     bar_width,
                     # with y1_label and y2_label on the left
                     left=[i + j for i, j in zip(df['y1_label'], df['y2_label'])],
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     hatch='//',
                     color='#3232FF'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y4_label'],
                     bar_width,
                     # with y1_label, y2_label and y3_label on the left
                     left=[i + j + q for i, j, q in zip(df['y1_label'], df['y2_label'], df['y3_label'])],
                     label='DDT',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     color='#3232FF'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                    # using the empty data
                    df['waiting'],
                    bar_width,
                    # with y1_label, y2_label, y3_label and y4_label on the left
                    left=[i + j + q + w for i, j, q, w in zip(df['y1_label'], df['y2_label'], df['y3_label'],
                                                              df['y4_label'])],
                    # with alpha 0
                    alpha=0,
                    # with color
                    color='black'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y5_label'],
                     bar_width,
                     # with y1_label, y2_label, y3_label, y4_label and 'waiting' on the left
                     left=[i + j + q + w + e for i, j, q, w, e in zip(df['y1_label'], df['y2_label'], df['y3_label'],
                                                                      df['y4_label'], df['waiting'])],
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     hatch='//',
                     color='#654321'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y6_label'],
                     bar_width,
                     # with y1_label, y2_label, y3_label, y4_label, waiting and y5_label on the left
                     left=[i + j + q + w + e + r for i, j, q, w, e, r in zip(df['y1_label'], df['y2_label'],
                                                                          df['y3_label'], df['y4_label'],
                                                                          df['waiting'], df['y5_label'])],
                     label='Collective Aggr.',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     color='#654321'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y7_label'],
                     bar_width,
                     # with y1_label, y2_label, y3_label, y4_label, waiting, y5_label and y6_label on the left
                     left=[i + j + q + w + e + r + t for i, j, q, w, e, r, t in zip(df['y1_label'],
                                                                                    df['y2_label'],
                                                                                    df['y3_label'],
                                                                                    df['y4_label'],
                                                                                    df['waiting'],
                                                                                    df['y5_label'],
                                                                                    df['y6_label'])],
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     hatch='//',
                     color='#a4bf0d'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y8_label'],
                     bar_width,
                     # with y1_label, y2_label, y3_label, y4_label, waiting, y5_label, y6_label and y7_label on the left
                     left=[i + j + q + w + e + r + t + z for i, j, q, w, e, r, t, z in zip(df['y1_label'],
                                                                                           df['y2_label'],
                                                                                           df['y3_label'],
                                                                                           df['y4_label'],
                                                                                           df['waiting'],
                                                                                           df['y5_label'],
                                                                                           df['y6_label'],
                                                                                           df['y7_label'])],
                     label='DRO',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     color='#a4bf0d'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y9_label'],
                     bar_width,
                     # with y1_label, y2_label, y3_label, y4_label, waiting, y5_label, y6_label, y7_label and y8_label
                     # on the left
                     left=[i + j + q + w + e + r + t + z + u for i, j, q, w, e, r, t, z, u in zip(df['y1_label'],
                                                                                           df['y2_label'],
                                                                                           df['y3_label'],
                                                                                           df['y4_label'],
                                                                                           df['waiting'],
                                                                                           df['y5_label'],
                                                                                           df['y6_label'],
                                                                                           df['y7_label'],
                                                                                           df['y8_label'])],
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     hatch='//',
                     color='#808080'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y10_label'],
                     bar_width,
                     # with y1_label, y2_label, y3_label, y4_label, waiting, y5_label, y6_label, y7_label, y8_label
                     # and y9_label on the left
                     left=[i + j + q + w + e + r + t + z + u + o for i, j, q, w, e, r, t, z, u, o in zip(df['y1_label'],
                                                                                           df['y2_label'],
                                                                                           df['y3_label'],
                                                                                           df['y4_label'],
                                                                                           df['waiting'],
                                                                                           df['y5_label'],
                                                                                           df['y6_label'],
                                                                                           df['y7_label'],
                                                                                           df['y8_label'],
                                                                                           df['y9_label'])],
                     label='Key Switch',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     color='#808080'))

# Set the y ticks with names
plt.yticks(tick_pos, df['h_label'])
ax1.xaxis.grid(True)

# Labelling
width = [0, 0, 0, 0, 0, 0]
for rects in bars:
    i = 0
    for rect in rects:
        width[i] += rect.get_width()
        i += 1

# Set the label and legends
ax1.set_xlabel("Runtime (s)", fontsize=22)
plt.legend(loc='upper center', ncol=2)

ax1.tick_params(axis='x', labelsize=24)
ax1.tick_params(axis='y', labelsize=24)

# Set a buffer around the edge
plt.ylim([min(tick_pos) - bar_width, max(tick_pos) + bar_width + 0.8])

plt.axvline(x=8.4, ymin=0, ymax = 10, linewidth=2, color='k')

plt.savefig('timeline.pdf', format='pdf')
