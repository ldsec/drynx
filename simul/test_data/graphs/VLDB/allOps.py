import matplotlib.pyplot as plt
import pandas as pd

font = {'family': 'Bitstream Vera Sans',
        'size': 16}

plt.rc('font', **font)

raw_data = {'operations': ['sum\n2', 'OR\n1', '', 'mean\n2', 'var\n3', 'cosim\n4', 'R$^{2}$\n4', 'log\n54',
                           'lin\n65', 'fc\n100', 'max\n100', '', 'inter\n100', ''],
            'execution':     [0.9, 0.9, 0, 0.9, 0.9, 0.9, 0.9, 1.2, 1.2, 1.8, 1.3, 0, 1.43, 0],
            'proofOverhead': [1.08, 0.98, 0, 1.67, 1.84, 2.94, 2.39, 11.2, 14.7, 23, 0.83, 0, 0.95, 0],
            'total': [2, 1.9, 2.1, 2.6, 2.7, 3.8, 3.2, 12.4, 15.9, 24.8, 2.2, 8, 2.4, 8.3],
            'executionObf':     [0, 0, 1.1, 0, 0, 0, 0, 0, 0, 0, 0, 2.1, 0, 2.3],
            'proofOverheadObf': [0, 0, 1.04, 0, 0, 0, 0, 0, 0, 0, 0, 5.89, 0, 5.96],
            'totalObf': [0, 0, 2.1, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 2.3],
            'empty': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}

df = pd.DataFrame(raw_data, raw_data['operations'])

# Create the general plot and the "subplots" i.e. the bars
f, ax = plt.subplots(1, figsize=(9, 7))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_Drynx = [1, 2.2, 2.7, 3.9, 5.1, 6.3, 7.5, 8.7, 9.9, 11.1, 12.3, 12.8, 14, 14.5]
bar_Obf = [1, 2.2, 2.7, 3.9, 5.1, 6.3, 7.5, 8.7, 9.9, 11.1, 12.3, 12.8, 14, 14.5]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [1, 2.45, 2.45, 3.9, 5.1, 6.3, 7.5, 8.7, 9.9, 11.1, 12.55, 12.55, 14.25, 14.25]

ax.bar(bar_Drynx, df['execution'], width=bar_width, label='Query Execution (w/o obf.)',
       alpha=0.8, color='#2f3e75')
ax.bar(bar_Drynx, df['proofOverhead'], width=bar_width, label='Proof Overhead (w/o obf.)',
       alpha=0.8, color='#d3c77e',
       bottom=df['execution'])

ax.bar(bar_Obf, df['executionObf'], width=bar_width, label='Query Execution (w/ obf.)',
       alpha=0.8, color='#D7C9AA', hatch='xx')
ax.bar(bar_Obf, df['proofOverheadObf'], width=bar_width, label='Proof Overhead (w/ obf.)',
       alpha=0.8, color='#0B7A75', hatch='xx',
       bottom=df['executionObf'])

# Set the x ticks with names
plt.xticks(tick_pos, df['operations'])
plt.legend(loc='upper left')

# Labelling
ax.text(bar_Drynx[0] - bar_width/2 + 0.1, df['total'][0] + 0.4, str(int(df['total'][0])),
        color='black', fontweight='bold')
ax.text(bar_Drynx[1] - bar_width/2 - 0.4, df['total'][1] + 0.4, str(df['total'][1]),
        color='black', fontweight='bold')
ax.text(bar_Drynx[2] - bar_width/2, df['total'][2] + 0.4, str(df['total'][2]),
        color='black', fontweight='bold')
ax.text(bar_Drynx[3] - bar_width/2 - 0.12, df['total'][3] + 0.4, str(df['total'][3]),
        color='black', fontweight='bold')
ax.text(bar_Drynx[4] - bar_width/2 - 0.12, df['total'][4] + 0.4, str(df['total'][4]),
        color='black', fontweight='bold')
ax.text(bar_Drynx[5] - bar_width/2 - 0.12, df['total'][5] + 0.4, str(df['total'][5]),
        color='black', fontweight='bold')
ax.text(bar_Drynx[6] - bar_width/2 - 0.12, df['total'][6] + 0.4, str(df['total'][6]),
        color='black', fontweight='bold')
ax.text(bar_Drynx[7] - bar_width/2 - 0.3, df['total'][7] + 0.4, str(df['total'][7]),
        color='black', fontweight='bold')
ax.text(bar_Drynx[8] - bar_width/2 - 0.3, df['total'][8] + 0.4, str(df['total'][8]),
        color='black', fontweight='bold')
ax.text(bar_Drynx[9] - bar_width/2 - 0.34, df['total'][9] + 0.4, str(df['total'][9]),
        color='black', fontweight='bold')
ax.text(bar_Drynx[10] - bar_width/2 - 0.4, df['total'][10] + 0.4, str(df['total'][10]),
        color='black', fontweight='bold')
ax.text(bar_Drynx[11] - bar_width/2 + 0.1, df['total'][11] + 0.4, str(int(df['total'][11])),
        color='black', fontweight='bold')
ax.text(bar_Drynx[12] - bar_width/2 - 0.4, df['total'][12] + 0.4, str(df['total'][12]),
        color='black', fontweight='bold')
ax.text(bar_Drynx[13] - bar_width/2 - 0.19, df['total'][13] + 0.4, str(df['total'][13]),
        color='black', fontweight='bold')

# Set the label and legends
ax.set_ylabel("Runtime (s)", fontsize=20)
ax.set_xlabel("Operation", fontsize=20)

ax.tick_params(axis='x', labelsize=15)
ax.tick_params(axis='y', labelsize=20)

# Set a buffer around the edge
plt.ylim(bottom=0, top=28)

plt.savefig('allOps.pdf', bbox_inches='tight', pad_inches=0)
