import matplotlib.pyplot as plt
import numpy as np

font = {'family': 'Bitstream Vera Sans',
        'size': 17}

plt.rc('font', **font)

totalNbrDPs = 8922


x = np.linspace(0, 10, num=100)

d = totalNbrDPs*x/100           # maliciousDPs
h = totalNbrDPs*(100-x)/100     # honestDPs
ah = 70
e = 100
c = 0

# Create the general plot and the "subplots"
f, ax = plt.subplots(1, figsize=(9, 7))

am = (h*ah+d*e)/(h+c)
y = np.absolute(1 - (am/ah)) * 100
ax.plot(x, y, label='Range: [40,100]', linestyle="--")

e = 256
am = (h*ah+d*e)/(h+c)
y = np.absolute(1 - (am/ah)) * 100
ax.plot(x, y, label='Range: [0,256]')

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
