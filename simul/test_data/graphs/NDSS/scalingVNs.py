import matplotlib.pyplot as plt
import pandas as pd

font = {'family': 'Bitstream Vera Sans',
        'size': 17}

plt.rc('font', **font)

raw_data = {'#servers': ['7', '14', '21', '28', '35', '42'],
            'execution': [0.89, 0.89, 0.89, 0.89, 0.89, 0.89],
            'proofOverhead': [1, 1.7, 2.2, 2.8, 3.5, 4.1],
            'blockInsertion': [0.4, 0.7, 0.9, 1, 1, 1.1],
            'total': [2.3, 3.3, 4, 4.7, 5.4, 6.1]}

df = pd.DataFrame(raw_data, raw_data['#servers'])

# Create the general plot and the "subplots" i.e. the bars
f, ax = plt.subplots(1, figsize=(9, 7))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_Drynx = [i + 1 for i in range(len(df['#servers']))]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [i for i in bar_Drynx]

ax.bar(bar_Drynx, df['execution'], width=bar_width, label='Query Execution', alpha=0.8, color='#2f3e75')
ax.bar(bar_Drynx, df['proofOverhead'], width=bar_width, label='Proof Overhead', alpha=0.8, color='#d3c77e',
       bottom=df['execution'])
ax.bar(bar_Drynx, df['blockInsertion'], width=bar_width, label='Block Insertion', alpha=0.9, color='#efa35c',
       bottom=[i + j for i, j in zip(df['execution'], df['proofOverhead'])])

# Set the x ticks with names
plt.xticks(tick_pos, df['#servers'])
plt.legend(loc='upper left')

# Labelling
ax.text(bar_Drynx[0] - bar_width/2 + 0.07, df['total'][0] + 0.1, str(df['total'][0]), color='black', fontweight='bold')
ax.text(bar_Drynx[1] - bar_width/2 + 0.07, df['total'][1] + 0.1, str(df['total'][1]), color='black', fontweight='bold')
ax.text(bar_Drynx[2] - bar_width/2 + 0.07, df['total'][2] + 0.1, str(df['total'][2]), color='black', fontweight='bold')
ax.text(bar_Drynx[3] - bar_width/2 + 0.07, df['total'][3] + 0.1, str(df['total'][3]), color='black', fontweight='bold')
ax.text(bar_Drynx[4] - bar_width/2 + 0.07, df['total'][4] + 0.1, str(df['total'][4]), color='black', fontweight='bold')
ax.text(bar_Drynx[5] - bar_width/2 + 0.07, df['total'][5] + 0.1, str(df['total'][5]), color='black', fontweight='bold')

# Set the label and legends
ax.set_ylabel("Runtime (s)", fontsize=20)
ax.set_xlabel("#VNs", fontsize=20)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

# Set a buffer around the edge
plt.ylim(ymin=0, ymax=12)

plt.savefig('scalingVNs.pdf', format='pdf')
