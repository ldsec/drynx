import matplotlib.pyplot as plt

font = {'family': 'Bitstream Vera Sans',
        'size': 16}

plt.rc('font', **font)

x = [0, 1, 10, 100, 500, 1000]
y = [100-0, 100-99.9548345, 100-99.5483915, 100-95.48856445, 100-77.54614258, 100-55.35058594]

# Create the general plot and the "subplots"
f, ax = plt.subplots(1, figsize=(9, 7))

ax.plot(x, y)
ax.set_xscale("log")

# Set the label and legends
ax.set_xlabel("#Malicious DPs", fontsize=20)
ax.set_ylabel("Distortion (%)", fontsize=20)

ax.tick_params(axis='x', labelsize=20)
ax.tick_params(axis='y', labelsize=20)

ax.grid()

plt.ylim(bottom=0, top=102)
plt.xlim(right=1000)

plt.savefig('maliciousDPs.pdf', bbox_inches='tight', pad_inches=0)
