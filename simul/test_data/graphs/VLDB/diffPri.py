import matplotlib.pyplot as plt
import pandas as pd

font = {'family': 'Bitstream Vera Sans',
        'size': 17}

plt.rc('font', **font)

raw_data = {'sizeNoiseList': ['0', '10k', '100k', '1M'],
            'execution':     [0.9, 9.7, 68.6, 721],
            'proofOverhead': [1.4, 72.2, 588, 5150],
            'total': [2.3, 81.9, 657, 5872],
            'empty': [0, 0, 0, 0]}

df = pd.DataFrame(raw_data, raw_data['sizeNoiseList'])

df['execution'] += 1

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

ax.set_yscale('log')

# Set the x ticks with names
plt.xticks(tick_pos, df['sizeNoiseList'])
plt.legend(loc='upper left')

# Labelling
ax.text(bar_Drynx[0] - bar_width/2 + 0.13, df['total'][0] + 1.2, str(df['total'][0]), color='black', fontweight='bold')
ax.text(bar_Drynx[1] - bar_width/2 + 0.08, df['total'][1] + 5, str(df['total'][1]), color='black', fontweight='bold')
ax.text(bar_Drynx[2] - bar_width/2 + 0.11, df['total'][2] + 40, str(int(df['total'][2])), color='black', fontweight='bold')
ax.text(bar_Drynx[3] - bar_width/2 + 0.05, df['total'][3] + 400, str(int(df['total'][3])), color='black', fontweight='bold')

# Set the label and legends
ax.set_ylabel("Runtime (s)", fontsize=20)
ax.set_xlabel("Size of noise values' list", fontsize=20)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

labels = [item.get_text() for item in ax.get_yticklabels()]
labels[1] = '0'
labels[2] = '10$^1$'
labels[3] = '10$^2$'
labels[4] = '10$^3$'
labels[5] = '10$^4$'
ax.set_yticklabels(labels)

# Set a buffer around the edge
plt.ylim(bottom=1, top=20000)

plt.savefig('diffPri.pdf', bbox_inches='tight', pad_inches=0)
