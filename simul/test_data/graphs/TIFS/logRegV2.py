import matplotlib.pyplot as plt
import pandas as pd

font = {'family': 'Bitstream Vera Sans',
        'size': 17}

plt.rc('font', **font)

raw_data = {'dataset': ['PIMA$_{(8,7680,450)}$', 'SPECTF$_{(44,2760, 200)}$', 'LBW$_{(10,3760,25)}$', 'PCS$_{(10,1890,25)}$'],
            'execution': [1.2, 12.1, 1.4, 1.4],
            'proofOverhead': [10.9, 180.59, 13.1, 13],
            'decode': [0.12, 4.1, 0.07, 0.07],
            'total': [12.2, 197, 14.5, 14.5],
            'empty': [0, 0, 0, 0]}

df = pd.DataFrame(raw_data, raw_data['dataset'])

df['execution'] += 1

# Create the general plot and the "subplots" i.e. the bars
f, ax = plt.subplots(1, figsize=(12, 7))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_LR = [1, 3, 5, 7]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [i for i in bar_LR]

ax.bar(bar_LR, df['execution'], width=bar_width, label='Query Execution', alpha=0.8, color='#2f3e75')
ax.bar(bar_LR, df['decode'], width=bar_width, label='Decode', alpha=0.8, color='#131200',
       bottom=df['execution'])
ax.bar(bar_LR, df['proofOverhead'], width=bar_width, label='Proof Overhead', alpha=0.8, color='#d3c77e',
       bottom=[i + j for i, j in zip(df['execution'], df['decode'])])

ax.set_yscale('log')

# Set the x ticks with names
plt.xticks(tick_pos, df['dataset'])
plt.legend(loc='upper right')

# Labelling
ax.text(bar_LR[0] - bar_width/2, df['total'][0] + 2.5, str(df['total'][0]), color='black', fontweight='bold')
ax.text(bar_LR[1] - bar_width/2 + 0.04, df['total'][1] + 20, str(int(df['total'][1])), color='black', fontweight='bold')
ax.text(bar_LR[2] - bar_width/2, df['total'][2] + 2.5, str(df['total'][2]), color='black', fontweight='bold')
ax.text(bar_LR[3] - bar_width/2, df['total'][3] + 2.5, str(df['total'][3]), color='black', fontweight='bold')

ax.text(bar_LR[0] - bar_width/2 + 0.02, df['execution'][0]+df['decode'][0] + 0.1,
        str(round(df['execution'][0]+df['decode'][0], 2)), color='black', fontweight='bold')
ax.text(bar_LR[1] - bar_width/2 + 0.02, df['execution'][1]+df['decode'][1] + 1,
        str(round(df['execution'][1]+df['decode'][1], 2)), color='black', fontweight='bold')
ax.text(bar_LR[2] - bar_width/2 + 0.02, df['execution'][2]+df['decode'][2] + 0.1,
        str(round(df['execution'][2]+df['decode'][2], 2)), color='black', fontweight='bold')
ax.text(bar_LR[3] - bar_width/2 + 0.02, df['execution'][3]+df['decode'][3] + 0.1,
        str(round(df['execution'][3]+df['decode'][3], 2)), color='black', fontweight='bold')

# Set the label and legends
ax.set_ylabel("Runtime (s)", fontsize=20)
ax.set_xlabel("Dataset$_{(features,observations,iterations)}$", fontsize=20)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

labels = [item.get_text() for item in ax.get_yticklabels()]
labels[1] = '0'
labels[2] = '10$^1$'
labels[3] = '10$^2$'
labels[4] = '10$^3$'
ax.set_yticklabels(labels)

# Set a buffer around the edge
plt.ylim(ymin=1, ymax=1000)
plt.xlim([min(bar_LR) - bar_width - 0.3, max(bar_LR) + bar_width + 0.2])

plt.savefig('logRegV2.pdf', bbox_inches='tight', pad_inches=0)
