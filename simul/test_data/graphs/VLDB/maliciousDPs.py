import matplotlib.pyplot as plt

font = {'family': 'Bitstream Vera Sans',
        'size': 17}

plt.rc('font', **font)

x = [0, 0.1, 1, 10]
y = [0, 0.143000143, 1.443001443, 15.87301587]
y1 = [0, 0.366080366, 3.694083694, 40.63492063]

# Create the general plot and the "subplots"
f, ax = plt.subplots(1, figsize=(9, 7))

ax.plot(x, y, label='Range: [40,100]', linestyle="--")
ax.plot(x, y1, label='Range: [0,256]')
ax.set_xscale("log")

# Set the label and legends
ax.set_xlabel("Percentage of malicious DPs (%)", fontsize=20)
ax.set_ylabel("Relative Error (%)", fontsize=20)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

ax.grid()
ax.legend()

plt.ylim(bottom=0, top=50)
plt.xlim(right=10)

labels = [item.get_text() for item in ax.get_xticklabels()]
labels[1] = '0'
labels[2] = '0.1'
labels[3] = '1'
labels[4] = '10'
ax.set_xticklabels(labels)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

plt.savefig('maliciousDPs.pdf', bbox_inches='tight', pad_inches=0)
