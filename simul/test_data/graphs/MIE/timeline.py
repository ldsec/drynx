import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

font = {'family': 'Bitstream Vera Sans',
        'size': 13}

plt.rc('font', **font)

raw_data = {'roles': ['$Q$', '$DPs_{CC}$', '$DPs_{LC}$'],
            # Q
            'queryCreation': [0.08, 0, 0],
            'waitingQ1': [16.25, 0, 0],
            'decode': [0.08, 0, 0],
            # CNs
            'waitingCN1': [0, 0.08, 0],
            'queryBroadcast': [0, 0.08, 0],
            'queryReencryption': [0, 0.24, 0],
            'waitingCN2': [0, 8.91, 0],
            'cta': [0, 3.32, 0],
            'keySwitching': [0, 3.7, 0], #true value 15.82
            # DPs
            'waitingDP1': [0, 0, 0.4],
            'dbExecution': [0, 0, 5],
            'resultRetrieval': [0, 0, 0.41],
            'dcp': [0, 0, 3.5],
            # Empty
            'empty': [0, 0, 0]}

df = pd.DataFrame(raw_data, raw_data['roles'])

df['queryCreation'] += 1
df['waitingCN1'] += 1
df['waitingDP1'] += 1

# Create the general plot and the "subplots" i.e. the bars
f, ax = plt.subplots(1, figsize=(9, 6))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_Drynx = [3.2, 2.57, 2]

# Positions of the y-axis ticks (center of the bars as bar labels)
tick_pos = [i for i in bar_Drynx]

# Querier
ax.barh(bar_Drynx, df['queryCreation'], bar_width, label='Query Creation', alpha=0.8, color='black')
ax.barh(bar_Drynx, df['waitingQ1'], bar_width, alpha=0, color='white',
        left=df['queryCreation'])
ax.barh(bar_Drynx, df['decode'], bar_width, label='Decode & Decrypt', alpha=0.8, color='#F0A202',
        left=[i + j for i, j in zip(df['queryCreation'], df['waitingQ1'])])

# DPs
ax.barh(bar_Drynx, df['waitingDP1'], bar_width, alpha=0, color='white')
ax.barh(bar_Drynx, df['dbExecution'], bar_width, label='DB Execution', alpha=0.8, color='#0B7A75',
        left=df['waitingDP1'])
ax.barh(bar_Drynx, df['resultRetrieval'], bar_width, label='Result Retrieval', alpha=0.8, color='#228de0',
        left=[i + j for i, j in zip(df['waitingDP1'], df['dbExecution'])])
ax.barh(bar_Drynx, df['dcp'], bar_width, label='Encoding', alpha=0.8, color='#3E2F5B',
        left=[i + j + k for i, j, k in zip(df['waitingDP1'],
                                           df['dbExecution'],
                                           df['resultRetrieval'])])

# CNs
ax.barh(bar_Drynx, df['waitingCN1'], bar_width, alpha=0, color='white')
ax.barh(bar_Drynx, df['queryBroadcast'], bar_width, label='Query Broadcast', alpha=0.8, color='#434a54',
        left=df['waitingCN1'])
ax.barh(bar_Drynx, df['queryReencryption'], bar_width, label='Query Reencryption', alpha=0.8, color='#8b4513',
        left=[i + j for i, j in zip(df['waitingCN1'], df['queryBroadcast'])])
ax.barh(bar_Drynx, df['waitingCN2'], bar_width, alpha=0, color='white',
        left=[i + j + k for i, j, k in zip(df['waitingCN1'], df['queryBroadcast'], df['queryReencryption'])])
ax.barh(bar_Drynx, df['cta'], bar_width, label='Collective Aggregation', alpha=0.8, color='#4E8098',
        left=[i + j + k + l for i, j, k, l in zip(df['waitingCN1'],
                                                  df['queryBroadcast'],
                                                  df['queryReencryption'],
                                                  df['waitingCN2'])])
ax.barh(bar_Drynx, df['keySwitching'], bar_width, label='Key Switching', alpha=0.8, color='#FB3640',
        left=[i + j + k + l + o for i, j, k, l, o in zip(df['waitingCN1'],
                                                         df['queryBroadcast'],
                                                         df['queryReencryption'],
                                                         df['waitingCN2'],
                                                         df['cta'])])

# Set the y ticks with names
plt.yticks(tick_pos, df['roles'])

# Set the label and legends
ax.set_xlabel("Runtime (s)", fontsize=20)
plt.legend(loc='upper center', ncol=2)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)
ax.xaxis.set_ticks(np.arange(0, 24, 0.5))

labels = [item.get_text() for item in ax.get_xticklabels()]
labels[2] = '0'
labels[4] = '2'
labels[11] = '74'
labels[15] = '76'
labels[19] = '78'
labels[23] = '80'
labels[27] = '82'
labels[31] = '84'
labels[35] = '98'
ax.set_xticklabels(labels)

ax.text(3.8, 3.6, 'Exploration', color='black', fontweight='bold')
ax.text(15.2, 3.6, 'Analysis', color='black', fontweight='bold')

# Set a buffer around the edge
plt.xlim(left=1, right=18)
plt.ylim([min(tick_pos) - bar_width, max(tick_pos) + bar_width + 2])

plt.axvline(x=6.81, ymin=0, ymax=0.67, linewidth=1.3, color='k', linestyle="--")
plt.axvline(x=17.41, ymin=0, ymax=10, linewidth=1.3, color='k', linestyle="--")

plt.savefig('timeline.pdf', bbox_inches='tight', pad_inches=0)
