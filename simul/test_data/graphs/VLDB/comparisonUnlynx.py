import matplotlib.pyplot as plt
import pandas as pd

font = {'family': 'Bitstream Vera Sans',
        'size': 17}

plt.rc('font', **font)

raw_data = {'sizeNoiseList': ['unlynx', 'drynx', '-', '-'],
            'execution':     [1, 0.9, 0, 0],
            'proofOverhead': [1, 1.4, 0, 0],
            'total': [2, 2.3, 0, 0]}

df = pd.DataFrame(raw_data, raw_data['sizeNoiseList'])

# Create the general plot and the "subplots" i.e. the bars
f, ax = plt.subplots(1, figsize=(9, 7))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_Drynx = [0, 1, 2, 3]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [i for i in bar_Drynx]

ax.bar(bar_Drynx, df['execution'], width=bar_width, label='Query Execution', alpha=0.8, color='#2f3e75')
ax.bar(bar_Drynx, df['proofOverhead'], width=bar_width, label='Proof Overhead', alpha=0.8, color='#d3c77e',
       bottom=df['execution'])

# Set the x ticks with names
plt.xticks(tick_pos, df['sizeNoiseList'])
plt.legend(loc='upper left')

# Labelling
ax.text(bar_Drynx[0] - bar_width/2 + 0.13, df['total'][0], str(df['total'][0]), color='black', fontweight='bold')
ax.text(bar_Drynx[1] - 0.11, df['total'][1] + 0.05, str(df['total'][1]), color='black', fontweight='bold')

# Set the label and legends
ax.set_ylabel("Runtime (s)", fontsize=20)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

# Set a buffer around the edge
plt.ylim(bottom=0, top=3.5)

plt.savefig('comparisonUnlynx.pdf', bbox_inches='tight', pad_inches=0)
