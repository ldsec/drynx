import matplotlib.pyplot as plt
import pandas as pd

font = {'family': 'Bitstream Vera Sans',
        'size': 26}
plt.rc('font', **font)

raw_data = {
    'x_label':  [50000, 100000, 200000, 400000, 800000, 1600000],
    'medco':  [3.4+62.7+0.2, 3.5+118+0.2, 3.5+245.1+0.2, 3.5+490+0.1, 3.5+972.3+0.2, 3.5+1930.2+0.2],
}

df = pd.DataFrame(raw_data, raw_data['x_label'])

fig, ax = plt.subplots(1, figsize=(17, 11))
ax.plot(raw_data['x_label'], raw_data['medco'],
        label='MedCo', linewidth=2, ls='--',
        marker='o', markersize=7)

ax.set_ylim([0, 2000])
ax.set_xlim([0, 1700000])

plt.setp(ax.get_yticklabels()[0], visible=False)

labels = [item.get_text() for item in ax.get_xticklabels()]
labels[0] = '0'
labels[1] = '200K'
labels[2] = '400K'
labels[3] = '600K'
labels[4] = '800K'
labels[5] = '1M'
labels[6] = '1.2M'
labels[7] = '1.4M'
labels[8] = '1.6M'
ax.set_xticklabels(labels)

# # Set the label and legends
ax.set_ylabel("Runtime (s)", fontsize=32)
ax.set_xlabel("Number of records per DP", fontsize=32)
plt.legend(loc='upper left', fontsize=32)

ax.tick_params(axis='x', labelsize=32)
ax.tick_params(axis='y', labelsize=32)

plt.savefig('logreg.pdf', format='pdf')