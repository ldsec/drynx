import matplotlib.pyplot as plt
import pandas as pd

font = {'family': 'Bitstream Vera Sans',
        'size': 17}

plt.rc('font', **font)

raw_data = {'thresholdMain': ['1.0', '0.5', '0.2'],
            'executionThresholdOther1': [0.9, 0.9, 0.9],
            'proofOverheadThresholdOther1': [1.9, 1.8, 1.5],
            'totalThresholdOther1': [2.8, 2.7, 2.4],
            'executionThresholdOther05': [0.9, 0.9, 0.9],
            'proofOverheadThresholdOther05': [1.5, 1.4, 1.4],
            'totalThresholdOther05': [2.4, 2.3, 2.3],
            'executionThresholdOther02': [0.9, 0.9, 0.9],
            'proofOverheadThresholdOther02': [1.4, 1.3, 1.3],
            'totalThresholdOther02': [2.3, 2.2, 2.2],
            'empty': [0, 0, 0]}

df = pd.DataFrame(raw_data, raw_data['thresholdMain'])

# Create the general plot and the "subplots" i.e. the bars
f, ax = plt.subplots(1, figsize=(9, 20))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_ThresholdOther1 = [1, 3, 5]
bar_ThresholdOther05 = [1.5, 3.5, 5.5]
bar_ThresholdOther02 = [2, 4, 6]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [1.5, 3.5, 5.5]

ax.bar(bar_ThresholdOther1, df['empty'], width=bar_width, alpha=1, color='white', edgecolor="black", label='T$_{sub}$ = 1.0')
ax.bar(bar_ThresholdOther1, df['empty'], width=bar_width, alpha=1, color='white', hatch="//", label='T$_{sub}$ = 0.5')
ax.bar(bar_ThresholdOther1, df['empty'], width=bar_width, alpha=1, color='white', hatch="x", label='T$_{sub}$ = 0.2')

ax.bar(bar_ThresholdOther1, df['executionThresholdOther1'], width=bar_width, label='Query Execution', alpha=0.8, color='#2f3e75')
ax.bar(bar_ThresholdOther1, df['proofOverheadThresholdOther1'], width=bar_width, label='Proof Overhead', alpha=0.8, color='#f3e595',
       bottom=df['executionThresholdOther1'])

ax.bar(bar_ThresholdOther05, df['executionThresholdOther05'], width=bar_width, alpha=0.6, color='#2f3e75', hatch="//")
ax.bar(bar_ThresholdOther05, df['proofOverheadThresholdOther05'], width=bar_width, alpha=0.6, color='#f3e595', hatch="//",
       bottom=df['executionThresholdOther05'])

ax.bar(bar_ThresholdOther02, df['executionThresholdOther02'], width=bar_width, alpha=0.4, color='#2f3e75', hatch="x")
ax.bar(bar_ThresholdOther02, df['proofOverheadThresholdOther02'], width=bar_width, alpha=0.4, color='#f3e595', hatch="x",
       bottom=df['executionThresholdOther02'])

# Set the x ticks with names
plt.xticks(tick_pos, df['thresholdMain'])
plt.legend(loc='upper right')

# Labelling
ax.text(bar_ThresholdOther1[0] - bar_width/2 + 0.07, df['totalThresholdOther1'][0] + 0.01, str(df['totalThresholdOther1'][0]), color='black', fontweight='bold')
ax.text(bar_ThresholdOther1[1] - bar_width/2 + 0.07, df['totalThresholdOther1'][1] + 0.01, str(df['totalThresholdOther1'][1]), color='black', fontweight='bold')
ax.text(bar_ThresholdOther1[2] - bar_width/2 + 0.07, df['totalThresholdOther1'][2] + 0.01, str(df['totalThresholdOther1'][2]), color='black', fontweight='bold')

ax.text(bar_ThresholdOther05[0] - bar_width/2 + 0.07, df['totalThresholdOther05'][0] + 0.01, str(df['totalThresholdOther05'][0]), color='black', fontweight='bold')
ax.text(bar_ThresholdOther05[1] - bar_width/2 + 0.07, df['totalThresholdOther05'][1] + 0.01, str(df['totalThresholdOther05'][1]), color='black', fontweight='bold')
ax.text(bar_ThresholdOther05[2] - bar_width/2 + 0.07, df['totalThresholdOther05'][2] + 0.01, str(df['totalThresholdOther05'][2]), color='black', fontweight='bold')

ax.text(bar_ThresholdOther02[0] - bar_width/2 + 0.07, df['totalThresholdOther02'][0] + 0.01, str(df['totalThresholdOther02'][0]), color='black', fontweight='bold')
ax.text(bar_ThresholdOther02[1] - bar_width/2 + 0.07, df['totalThresholdOther02'][1] + 0.01, str(df['totalThresholdOther02'][1]), color='black', fontweight='bold')
ax.text(bar_ThresholdOther02[2] - bar_width/2 + 0.07, df['totalThresholdOther02'][2] + 0.01, str(df['totalThresholdOther02'][2]), color='black', fontweight='bold')


# Set the label and legends
ax.set_ylabel("Runtime (s)", fontsize=20)
ax.set_xlabel("Threshold_T (Ratio)", fontsize=20)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

plt.ylim(top=3.2)
plt.axhline(y=2.1, linewidth=2, color='k', linestyle='--', label='T = T$_{sub}$ = 0')
plt.legend()

plt.savefig('threshold.pdf', bbox_inches='tight', pad_inches=0)
