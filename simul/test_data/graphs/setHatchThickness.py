import os
import re

import matplotlib


def setHatchThickness(value):
    libpath = matplotlib.__path__[0]
    backend_pdf = libpath + "/backends/backend_pdf.py"
    with open(backend_pdf, "r") as r:
        code = r.read()
        code = re.sub(r'self\.output\((\d+\.\d+|\d+)\,\ Op\.setlinewidth\)',
                      "self.output(%s, Op.setlinewidth)" % str(value), code)
        with open('/tmp/hatch.tmp', "w") as w:
            w.write(code)
        os.system('sudo mv /tmp/hatch.tmp %s' % backend_pdf)


setHatchThickness(1.0)
