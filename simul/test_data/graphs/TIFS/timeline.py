import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

font = {'family': 'Bitstream Vera Sans',
        'size': 15}

plt.rc('font', **font)

raw_data = {'roles': ['Q', 'CNs', 'DPs', 'VNs', '', ''],
            'queryCreation': [0.02, 0, 0, 0, 0, 0],
            'waitingQ': [1.88, 0, 0, 0, 0, 0],
            'decode': [0.06, 0, 0, 0, 0, 0],
            'waitingCN1': [0, 0.02, 0, 0, 0, 0],
            'queryBroadcast': [0, 0.02, 0, 0, 0, 0],
            'waitingCN2': [0, 0.83, 0, 0, 0, 0],
            'collectiveAggregation': [0, 0.49, 0, 0, 0, 0],
            'keySwitching': [0, 0.52, 0, 0, 0, 0],
            'waitingDP1': [0, 0, 0.04, 0, 0, 0],
            'dcp': [0, 0, 0.79, 0, 0, 0],
            'waitingVN1': [0, 0, 0, 0.02, 0, 0],
            'queryAnalysis': [0, 0, 0, 0.02, 0, 0],
            'waitingVN2': [0, 0, 0, 0.2, 0, 0],
            'verifRanges': [0, 0, 0, 21.73, 0, 0],
            'waitVN3': [0, 0, 0, 0, 0, 0],
            'bi': [0, 0, 0, 0.44, 0, 0],
            'waitingVN4': [0, 0, 0, 0, 0.9, 0],
            'verifCA': [0, 0, 0, 0, 0.60, 0],
            'waitingVN5': [0, 0, 0, 0, 0, 1.55],
            'verifKS': [0, 0, 0, 0, 0, 2],
            'empty': [0, 0, 0, 0, 0, 0]}

df = pd.DataFrame(raw_data, raw_data['roles'])

df['queryCreation'] += 1
df['waitingCN1'] += 1
df['waitingDP1'] += 1
df['waitingVN1'] += 1
df['waitingVN4'] += 1
df['waitingVN5'] += 1

# Create the general plot and the "subplots" i.e. the bars
f, ax = plt.subplots(1, figsize=(9, 8))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_Drynx = [5, 4.3, 3.6, 2.9, 2.4, 1.9]

# Positions of the y-axis ticks (center of the bars as bar labels)
tick_pos = [i for i in bar_Drynx]

# Querier
ax.barh(bar_Drynx, df['queryCreation'], bar_width, label='Query Creation', alpha=0.8, color='black')
ax.barh(bar_Drynx, df['waitingQ'], bar_width, alpha=0, color='white',
        left=df['queryCreation'])

# DPs
ax.barh(bar_Drynx, df['waitingDP1'], bar_width, alpha=0, color='white')
ax.barh(bar_Drynx, df['dcp'], bar_width, label='Retrieval & Encoding', alpha=0.8, color='#0B7A75',
        left=df['waitingDP1'])

# CNs
ax.barh(bar_Drynx, df['waitingCN1'], bar_width, alpha=0, color='white')
ax.barh(bar_Drynx, df['queryBroadcast'], bar_width, label='Query Broadcast', alpha=0.8, color='#8b4513',
        left=df['waitingCN1'])
ax.barh(bar_Drynx, df['waitingCN2'], bar_width, alpha=0, color='white',
        left=[i + j for i, j in zip(df['waitingCN1'], df['queryBroadcast'])])
ax.barh(bar_Drynx, df['collectiveAggregation'], bar_width, label='CTA', alpha=0.8, color='#3C4F76',
        left=[i + j + k for i, j, k in zip(df['waitingCN1'], df['queryBroadcast'], df['waitingCN2'])])
ax.barh(bar_Drynx, df['keySwitching'], bar_width, label='CTKS', alpha=0.8, color='#AB9F9D',
        left=[i + j + k + l for i, j, k, l in zip(df['waitingCN1'],
                                                  df['queryBroadcast'],
                                                  df['waitingCN2'],
                                                  df['collectiveAggregation'])])

ax.barh(bar_Drynx, df['decode'], bar_width, label='Decoding', alpha=0.8, color='#DDDBF1',
        left=[i + j for i, j in zip(df['queryCreation'], df['waitingQ'])])

# VNs
ax.barh(bar_Drynx, df['waitingVN1'], bar_width, alpha=0, color='white')
ax.barh(bar_Drynx, df['queryAnalysis'], bar_width, label='Query Check', alpha=0.8, color='#AD343E',
        left=df['waitingVN1'])
ax.barh(bar_Drynx, df['waitingVN2'], bar_width, alpha=0, color='white',
        left=[i + j for i, j in zip(df['waitingVN1'], df['queryAnalysis'])])
ax.barh(bar_Drynx, df['verifRanges'], bar_width, label='Verify Range Proofs', alpha=0.6, color='#0B7A75', hatch="xx",
        left=[i + j + k for i, j, k in zip(df['waitingVN1'], df['queryAnalysis'], df['waitingVN2'])])
ax.barh(bar_Drynx, df['waitVN3'], bar_width, alpha=0, color='white',
        left=[i + j + k + l for i, j, k, l in zip(df['waitingVN1'],
                                                  df['queryAnalysis'],
                                                  df['waitingVN2'],
                                                  df['verifRanges'])])

ax.barh(bar_Drynx, df['waitingVN4'], bar_width, alpha=0, color='white')
ax.barh(bar_Drynx, df['verifCA'], bar_width, label='Verify CTA Proofs', alpha=0.6, color='#3C4F76',
        left=df['waitingVN4'], hatch="//")

ax.barh(bar_Drynx, df['waitingVN5'], bar_width, alpha=0, color='white')
ax.barh(bar_Drynx, df['verifKS'], bar_width, label='Verify CTKS Proofs', alpha=0.6, color='#AB9F9D',
        left=df['waitingVN5'], hatch="oo")

ax.barh(bar_Drynx, df['bi'], bar_width, label='Block Insertion', alpha=0.8, color='#F2AF29',
        left=[i + j + k + l + o for i, j, k, l, o in zip(df['waitingVN1'],
                                                         df['queryAnalysis'],
                                                         df['waitingVN2'],
                                                         df['verifRanges'],
                                                         df['waitVN3'])])

ax.set_xscale('log')

# Set the y ticks with names
plt.yticks(tick_pos, df['roles'])

# Set the label and legends
ax.set_xlabel("Runtime (s)", fontsize=20)
plt.legend(loc='upper center', ncol=2)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)
ax.xaxis.set_ticks(np.arange(0, 24, 1))

labels = [item.get_text() for item in ax.get_xticklabels()]
labels[1] = '0'
labels[2] = '1'
labels[4] = '3'
labels[6] = '5'
labels[8] = '7'
labels[11] = '10'
labels[21] = '20'
ax.set_xticklabels(labels)

ax.text(1.15, 5.3, 'Query Execution', color='black', fontweight='bold')
ax.text(9.3, 1.7, 'Proof Overhead', color='black', fontweight='bold')

# Set a buffer around the edge
plt.xlim(left=1, right=25)
plt.ylim([min(tick_pos) - bar_width, max(tick_pos) + bar_width + 2])

plt.axvline(x=2.96, ymin=0, ymax=0.67, linewidth=2, color='k', linestyle="--")
plt.axvline(x=23.41, ymin=0, ymax=10, linewidth=2, color='k', linestyle="--")

plt.savefig('timeline.pdf', bbox_inches='tight', pad_inches=0)
