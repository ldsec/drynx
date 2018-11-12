
def savefig_no_margins(plt, name):
    # Set a buffer around the edge
    plt.ylim(bottom=1, top=10000)
    plt.gca().set_axis_off()
    plt.subplots_adjust(top=1, bottom=0, right=1, left=0, hspace=0, wspace=0)
    plt.margins(0, 0)
    plt.gca().xaxis.set_major_locator(plt.NullLocator())
    plt.gca().yaxis.set_major_locator(plt.NullLocator())
    plt.savefig(name, bbox_inches='tight', pad_inches=0)
