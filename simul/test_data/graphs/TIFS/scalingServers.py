import matplotlib.pyplot as plt
import pandas as pd

font = {'family': 'Bitstream Vera Sans',
        'size': 17}

plt.rc('font', **font)

raw_data = {'#CNs': ['6', '12', '18', '24', '30', '36', '42', '48'],
            'execution':     [0.9, 1.2, 1.5, 1.6, 1.7, 1.9, 1.95, 2],
            'proofOverhead': [1.4, 3.5, 5, 7, 9.4, 13.2, 17.3, 21.2],
            'total': [2.3, 4.7, 6.5, 8.6, 11.1, 15.1, 19.3, 23.2]}

df = pd.DataFrame(raw_data, raw_data['#CNs'])

# Create the general plot and the "subplots" i.e. the bars
f, ax = plt.subplots(1, figsize=(9, 7))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_Drynx = [i + 1 for i in range(len(df['#CNs']))]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [i for i in bar_Drynx]

ax.bar(bar_Drynx, df['execution'], width=bar_width, label='Query Execution', alpha=0.8, color='#2f3e75')
ax.bar(bar_Drynx, df['proofOverhead'], width=bar_width, label='Proof Overhead', alpha=0.8, color='#d3c77e',
       bottom=df['execution'])

# Set the x ticks with names
plt.xticks(tick_pos, df['#CNs'])
plt.legend(loc='upper left')

# Labelling
ax.text(bar_Drynx[0] - bar_width/2, df['total'][0] + 0.4, str(df['total'][0]), color='black', fontweight='bold')
ax.text(bar_Drynx[1] - bar_width/2, df['total'][1] + 0.4, str(df['total'][1]), color='black', fontweight='bold')
ax.text(bar_Drynx[2] - bar_width/2, df['total'][2] + 0.4, str(df['total'][2]), color='black', fontweight='bold')
ax.text(bar_Drynx[3] - bar_width/2, df['total'][3] + 0.4, str(df['total'][3]), color='black', fontweight='bold')
ax.text(bar_Drynx[4] - bar_width/2 - 0.07, df['total'][4] + 0.4, str(df['total'][4]), color='black', fontweight='bold')
ax.text(bar_Drynx[5] - bar_width/2 - 0.07, df['total'][5] + 0.4, str(df['total'][5]), color='black', fontweight='bold')
ax.text(bar_Drynx[6] - bar_width/2 - 0.07, df['total'][6] + 0.4, str(df['total'][6]), color='black', fontweight='bold')
ax.text(bar_Drynx[7] - bar_width/2 - 0.07, df['total'][7] + 0.4, str(df['total'][7]), color='black', fontweight='bold')

# Set the label and legends
ax.set_ylabel("Runtime (s)", fontsize=20)
ax.set_xlabel("#CNs", fontsize=20)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

# Set a buffer around the edge
plt.ylim(bottom=0, top=30)

plt.savefig('scalingServers.pdf', bbox_inches='tight', pad_inches=0)
