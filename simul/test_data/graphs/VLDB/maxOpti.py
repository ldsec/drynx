import matplotlib.pyplot as plt
import pandas as pd

font = {'family': 'Bitstream Vera Sans',
        'size': 17}

plt.rc('font', **font)

raw_data = {'range': ['1k', '10k', '100k', '1M'],
            'execution': [3.2, 12, 76.32, 639],
            'proofOverhead': [2.3, 16.44, 170.08, 1587],
            'total': [5.5, 28.5, 246, 2226],
            'totalOptimized': [5.6, 7.6, 9.6, 11.3]}

df = pd.DataFrame(raw_data, raw_data['range'])

df['execution'] += 1
df['totalOptimized'] += 1

# Create the general plot and the "subplots" i.e. the bars
f, ax = plt.subplots(1, figsize=(9, 7))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_NonOpti = [1, 2.5, 4, 5.5]
bar_Opti = [1.5, 3, 4.5, 6]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [(pos + bar_width/2) for pos in bar_NonOpti]

ax.bar(bar_NonOpti, df['execution'], width=bar_width, label='Query Execution', alpha=0.8, color='#2f3e75')
ax.bar(bar_NonOpti, df['proofOverhead'], width=bar_width, label='Proof Overhead', alpha=0.8, color='#d3c77e',
       bottom=df['execution'])

ax.bar(bar_Opti, df['totalOptimized'], label='Optimized (iterative) max',  width=bar_width, alpha=0.8, color='#0B7A75')

ax.set_yscale('log')

# Set the x ticks with names
plt.xticks(tick_pos, df['range'])
plt.legend(loc='upper left')

# Labelling

ax.text(bar_NonOpti[0] - bar_width/2 + 0.08, df['total'][0] + 1.5, str(df['total'][0]), color='black', fontweight='bold')
ax.text(bar_NonOpti[1] - bar_width/2, df['total'][1] + 3.5, str(df['total'][1]), color='black', fontweight='bold')
ax.text(bar_NonOpti[2] - bar_width/2 + 0.04, df['total'][2] + 15, str(int(df['total'][2])), color='black', fontweight='bold')
ax.text(bar_NonOpti[3] - bar_width/2 - 0.04, df['total'][3] + 150, str(int(df['total'][3])), color='black', fontweight='bold')

ax.text(bar_Opti[0] - bar_width/2 + 0.08, df['totalOptimized'][0] + 0.3, str(df['totalOptimized'][0]-1), color='black', fontweight='bold')
ax.text(bar_Opti[1] - bar_width/2 + 0.08, df['totalOptimized'][1] + 0.4, str(df['totalOptimized'][1]-1), color='black', fontweight='bold')
ax.text(bar_Opti[2] - bar_width/2 + 0.06, df['totalOptimized'][2] + 0.5, str(df['totalOptimized'][2]-1), color='black', fontweight='bold')
ax.text(bar_Opti[3] - bar_width/2 + 0.06, df['totalOptimized'][3] + 0.5, str(df['totalOptimized'][3]-1), color='black', fontweight='bold')

# Set the label and legends
ax.set_ylabel("Runtime (s)", fontsize=20)
ax.set_xlabel("Range Size", fontsize=20)

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
plt.ylim(bottom=1, top=5000)

plt.savefig('maxOpti.pdf', bbox_inches='tight', pad_inches=0)
