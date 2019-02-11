import matplotlib.pyplot as plt
import pandas as pd

font = {'family': 'Bitstream Vera Sans',
        'size': 16}

plt.rc('font', **font)

raw_data = {'#servers': ['6(6)', '12(12)', '24(24)', '48(48)'],
            'executionDrynx': [3, 4.2, 5.2, 6.4],
            'verificationDrynx': [2.2, 3.1, 4.8, 8.5],
            'totalDrynx': [5.2, 7.3, 10, 15],
            'executionDrynxObf': [5.9, 9.1, 13.4, 20.7],
            'verificationDrynxObf': [10.9-4.72, 28.7-10.39, 82.2-48.19, 223.1-150],
            'totalDrynxObf': [16.8, 37.8, 95.6, 244],
            'executionDrynxHonest': [5.62, 8.71, 14.27, 23.04],
            'verificationDrynxHonest': [4.72, 10.39, 48.19, 150],
            'totalDrynxHonest': [10.3, 19.1, 62.4, 173],
            'aggregationPrio': [0.9, 1.42, 1.95, 2.63],
            'verificationPrio': [21, 41, 113, 286],
            'totalPrio': [21.9, 42.4, 115, 289],
            'empty': [0, 0, 0, 0]}

df = pd.DataFrame(raw_data, raw_data['#servers'])

# Create the general plot and the "subplots" i.e. the bars
f, ax = plt.subplots(1, figsize=(9, 7))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_Drynx = [1, 3, 5, 7]
bar_DrynxObf = [1.5, 3.5, 5.5, 7.5]
bar_Prio = [2, 4, 6, 8]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [(pos + bar_width/2) for pos in bar_DrynxObf]

ax.bar(bar_DrynxObf, df['empty'], width=bar_width, alpha=1, color='white', label='Drynx Threat Model', hatch="xx")

ax.bar(bar_Drynx, df['executionDrynx'], width=bar_width, label='Query Execution (w/o obf.)', alpha=0.8, color='#2f3e75')
ax.bar(bar_Drynx, df['verificationDrynx'], width=bar_width, label='Proof Overhead (w/o obf.)', alpha=0.8, color='#d3c77e',
       bottom=df['executionDrynx'])

ax.bar(bar_DrynxObf, df['executionDrynxObf'], width=bar_width, label='Query Execution (w/ obf.)', alpha=0.8, color='#D7C9AA', hatch="//")
ax.bar(bar_DrynxObf, df['verificationDrynxHonest'], width=bar_width, label='Proof Overhead (w/ obf.)', alpha=0.8, color='#0B7A75', hatch="//",
       bottom=df['executionDrynxObf'])
ax.bar(bar_DrynxObf, df['verificationDrynxObf'], width=bar_width, alpha=0.6, color='#0B7A75', hatch="xx",
       bottom=[i + j for i, j in zip(df['executionDrynxObf'], df['verificationDrynxHonest'])])

ax.bar(bar_Prio, df['aggregationPrio'], width=bar_width, label='Prio Aggregation', alpha=0.8, color='#232931')
ax.bar(bar_Prio, df['verificationPrio'], width=bar_width, label='Prio Verification', alpha=0.8, color='#ff7a5c',
       bottom=df['aggregationPrio'])

# Set the x ticks with names
plt.xticks(tick_pos, df['#servers'])
plt.legend(loc='upper left')

# Labelling
ax.text(bar_Drynx[0] - bar_width/2 + 0.06, df['totalDrynx'][0] + 4, str(df['totalDrynx'][0]), color='black', fontweight='bold', fontsize=13)
ax.text(bar_Drynx[1] - bar_width/2 + 0.06, df['totalDrynx'][1] + 4, str(df['totalDrynx'][1]), color='black', fontweight='bold', fontsize=13)
ax.text(bar_Drynx[2] - bar_width/2 + 0.11, df['totalDrynx'][2] + 4, str(int(df['totalDrynx'][2])), color='black', fontweight='bold', fontsize=13)
ax.text(bar_Drynx[3] - bar_width/2 + 0.11, df['totalDrynx'][3] + 4, str(int(df['totalDrynx'][3])), color='black', fontweight='bold', fontsize=13)

ax.text(bar_DrynxObf[0] - bar_width/2 - 0.12, df['totalDrynxObf'][0] + 5, str(df['totalDrynxObf'][0]), color='black', fontweight='bold', fontsize=13)
ax.text(bar_DrynxObf[1] - bar_width/2 - 0.12, df['totalDrynxObf'][1] + 5, str(df['totalDrynxObf'][1]), color='black', fontweight='bold', fontsize=13)
ax.text(bar_DrynxObf[2] - bar_width/2 - 0.08, df['totalDrynxObf'][2] + 6, str(df['totalDrynxObf'][2]), color='black', fontweight='bold', fontsize=13)
ax.text(bar_DrynxObf[3] - bar_width/2 - 0.02, df['totalDrynxObf'][3] + 6, str(int(df['totalDrynxObf'][3])), color='black', fontweight='bold', fontsize=13)

ax.text(bar_Prio[0] - bar_width/2, df['totalPrio'][0] + 6, str(df['totalPrio'][0]), color='black', fontweight='bold', fontsize=13)
ax.text(bar_Prio[1] - bar_width/2, df['totalPrio'][1] + 7, str(df['totalPrio'][1]), color='black', fontweight='bold', fontsize=13)
ax.text(bar_Prio[2] - bar_width/2, df['totalPrio'][2] + 4, str(int(df['totalPrio'][2])), color='black', fontweight='bold', fontsize=13)
ax.text(bar_Prio[3] - bar_width/2, df['totalPrio'][3] + 4, str(int(df['totalPrio'][3])), color='black', fontweight='bold', fontsize=13)

# Set the label and legends
ax.set_ylabel("Runtime (s)", fontsize=20)
ax.set_xlabel("#CNs(#DPs)", fontsize=20)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

# Set a buffer around the edge
plt.ylim(bottom=0, top=310)
plt.xlim([min(bar_Drynx) - bar_width - 0.2, max(bar_Prio) + bar_width + 0.2])

plt.axhline(xmin=0.115, xmax=0.17,  y=10.62, linewidth=2, color='k', label="Honest-but-curious Model")
plt.axhline(xmin=0.351, xmax=0.411, y=19.49, linewidth=2, color='k')
plt.axhline(xmin=0.56, xmax=0.67, y=61.59, linewidth=2, color='k')
plt.axhline(xmin=0.8, xmax=0.91, y=170.7, linewidth=2, color='k')
plt.legend()

plt.savefig('comparisonPrio.pdf', bbox_inches='tight', pad_inches=0)
