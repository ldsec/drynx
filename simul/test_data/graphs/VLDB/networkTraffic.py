import matplotlib.pyplot as plt
import pandas as pd

font = {'family': 'Bitstream Vera Sans',
        'size': 17}

plt.rc('font', **font)

raw_data = {'delay': ['20', '40', '80'],
            'executionFullBandwidth': [0.9, 2.1, 4.2],
            'proofOverheadFullBandwidth': [1.4, 1.4, 2.3],
            'totalFullBandwidth': [2.3, 3.5, 6.6],
            'executionHalfBandwidth': [1.27, 2.27, 4.3],
            'proofOverheadHalfBandwidth': [7.5, 7.6, 7.8],
            'totalHalfBandwidth': [9.1, 9.8, 11.9],
            'empty': [0, 0, 0]}

df = pd.DataFrame(raw_data, raw_data['delay'])

# Create the general plot and the "subplots" i.e. the bars
f, ax = plt.subplots(1, figsize=(9, 7))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_FullBandwidth = [1, 2.5, 4]
bar_HalfBandwidth = [1.5, 3, 4.5]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [(pos + bar_width/2) for pos in bar_FullBandwidth]

ax.bar(bar_HalfBandwidth, df['empty'], width=bar_width, alpha=1, color='white', edgecolor="black", label='Bandwith: 100Mb/s')
ax.bar(bar_HalfBandwidth, df['empty'], width=bar_width, alpha=1, color='white', hatch="xx", label='Bandwith: 1Mb/s')

ax.bar(bar_FullBandwidth, df['executionFullBandwidth'], width=bar_width, label='Query Execution', alpha=0.8, color='#2f3e75')
ax.bar(bar_FullBandwidth, df['proofOverheadFullBandwidth'], width=bar_width, label='Proof Overhead', alpha=0.8, color='#d3c77e',
       bottom=df['executionFullBandwidth'])

ax.bar(bar_HalfBandwidth, df['executionHalfBandwidth'], width=bar_width, alpha=0.6, color='#2f3e75', hatch="xx")
ax.bar(bar_HalfBandwidth, df['proofOverheadHalfBandwidth'], width=bar_width, alpha=0.6, color='#d3c77e', hatch="xx",
       bottom=df['executionHalfBandwidth'])

# Set the x ticks with names
plt.xticks(tick_pos, df['delay'])
plt.legend(loc='upper left')

# Labelling
ax.text(bar_FullBandwidth[0] - bar_width/2 + 0.12, df['totalFullBandwidth'][0] + 0.2, str(df['totalFullBandwidth'][0]), color='black', fontweight='bold')
ax.text(bar_FullBandwidth[1] - bar_width/2 + 0.12, df['totalFullBandwidth'][1] + 0.2, str(df['totalFullBandwidth'][1]), color='black', fontweight='bold')
ax.text(bar_FullBandwidth[2] - bar_width/2 + 0.12, df['totalFullBandwidth'][2] + 0.1, str(df['totalFullBandwidth'][2]), color='black', fontweight='bold')

ax.text(bar_HalfBandwidth[0] - bar_width/2 + 0.12, df['totalHalfBandwidth'][0] - 0.1, str(df['totalHalfBandwidth'][0]), color='black', fontweight='bold')
ax.text(bar_HalfBandwidth[1] - bar_width/2 + 0.12, df['totalHalfBandwidth'][1] + 0.3, str(df['totalHalfBandwidth'][1]), color='black', fontweight='bold')
ax.text(bar_HalfBandwidth[2] - bar_width/2 + 0.06, df['totalHalfBandwidth'][2] + 0.5, str(df['totalHalfBandwidth'][2]), color='black', fontweight='bold')

# Set the label and legends
ax.set_ylabel("Runtime (s)", fontsize=20)
ax.set_xlabel("Delay (ms)", fontsize=20)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

plt.ylim(top=16)

plt.savefig('networkTraffic.pdf', bbox_inches='tight', pad_inches=0)
