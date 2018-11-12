import matplotlib.pyplot as plt
import pandas as pd
import savefig as save

font = {'family': 'Bitstream Vera Sans',
        'size': 17}

plt.rc('font', **font)

raw_data = {'#records': ['600', '6k', '60k', '600k'],
            'executionFixedDPs': [0.89, 0.91, 1, 1.5],
            'proofOverheadFixedDPs': [1.3, 2.55, 2.76, 2.84],
            'totalFixedDPs': [2.2, 3.4, 3.8, 4.4],
            'executionVaryingDPs': [1.1, 1.9, 7.7, 57.2],
            'proofOverheadVaryingDPs': [8.6, 61, 481.2, 3230],
            'totalVaryingDPs': [9.7, 62.9, 489, 3287],
            'empty': [0, 0, 0, 0]}

df = pd.DataFrame(raw_data, raw_data['#records'])

df['executionFixedDPs'] += 1
df['executionVaryingDPs'] += 1

# Create the general plot and the "subplots" i.e. the bars
f, ax = plt.subplots(1, figsize=(9, 7))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_DrynxFixed = [1, 2.6, 4.2, 5.7]
bar_DrynxVarying = [1.6, 3.2, 4.8, 6.3]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [i - (bar_width/2) - 0.05 for i in bar_DrynxVarying]

ax.bar(bar_DrynxFixed, df['empty'], width=bar_width, alpha=1, color='white', label='#DPs = 10', edgecolor="black")
ax.bar(bar_DrynxFixed, df['empty'], width=bar_width, alpha=1, color='white', label='#DPs = #Records', hatch="xx")

ax.bar(bar_DrynxFixed, df['executionFixedDPs'], width=bar_width, label='Query Execution', alpha=0.8, color='#2f3e75')
ax.bar(bar_DrynxFixed, df['proofOverheadFixedDPs'], width=bar_width, label='Proof Overhead', alpha=0.8, color='#d3c77e',
       bottom=df['executionFixedDPs'])

ax.bar(bar_DrynxVarying, df['executionVaryingDPs'], width=bar_width, label='Query Execution', alpha=0.6, color='#2f3e75', hatch="xx")
ax.bar(bar_DrynxVarying, df['proofOverheadVaryingDPs'], width=bar_width, label='Proof Overhead', alpha=0.6, color='#d3c77e', hatch="xx",
       bottom=df['executionVaryingDPs'])

ax.set_yscale('log')

# Set the x ticks with names
plt.xticks(tick_pos, df['#records'])
plt.legend(loc='upper left')

# Labelling
ax.text(bar_DrynxFixed[0] - bar_width/2 + 0.06, df['totalFixedDPs'][0] + 1.5, str(df['totalFixedDPs'][0]), color='black', fontweight='bold')
ax.text(bar_DrynxFixed[1] - bar_width/2 + 0.06, df['totalFixedDPs'][1] + 1.5, str(df['totalFixedDPs'][1]), color='black', fontweight='bold')
ax.text(bar_DrynxFixed[2] - bar_width/2 + 0.06, df['totalFixedDPs'][2] + 1.5, str(df['totalFixedDPs'][2]), color='black', fontweight='bold')
ax.text(bar_DrynxFixed[3] - bar_width/2 + 0.06, df['totalFixedDPs'][3] + 1.5, str(df['totalFixedDPs'][3]), color='black', fontweight='bold')

ax.text(bar_DrynxVarying[0] - bar_width/2 + 0.07, df['totalVaryingDPs'][0] + 2, str(df['totalVaryingDPs'][0]), color='black', fontweight='bold')
ax.text(bar_DrynxVarying[1] - bar_width/2 - 0.01, df['totalVaryingDPs'][1] + 9, str(df['totalVaryingDPs'][1]), color='black', fontweight='bold')
ax.text(bar_DrynxVarying[2] - bar_width/2 + 0.03, df['totalVaryingDPs'][2] + 60, str(int(df['totalVaryingDPs'][2])), color='black', fontweight='bold')
ax.text(bar_DrynxVarying[3] - bar_width/2 - 0.04, df['totalVaryingDPs'][3] + 500, str(int(df['totalVaryingDPs'][3])), color='black', fontweight='bold')

# Set the label and legends
ax.set_ylabel("Runtime (s)", fontsize=20)
ax.set_xlabel("#Records", fontsize=20)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

labels = [item.get_text() for item in ax.get_yticklabels()]
labels[1] = '0'
labels[2] = '10$^1$'
labels[3] = '10$^2$'
labels[4] = '10$^3$'
labels[5] = '10$^4$'
ax.set_yticklabels(labels)

save.savefig_no_margins(plt, 'scalingDPs.pdf')
