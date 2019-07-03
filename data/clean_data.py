#!/usr/bin/python3

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def removeColumn(tab, index):
    for i in range(len(tab)):
        del tab[i][index]


"""
@brief cleanData clean some specific datasets
@param dataset string, available datasets are : PCS, PIMA, SPECTF, MNIST, GAS_SENSOR_MULTI
@param filename string, the filename of dataset which will be cleaned
"""

def cleanData(dataset, filename, label_type):
    
    if label_type == "int":
        label_type = int
    elif label_type == "float":
        label_type = float
    else:
        raise(ValueError(f"Unknow type {label_type}"))

    dataset = dataset.upper()

    with open(filename, "r") as fichier:
        dataString = fichier.read()

    dataString = dataString.split('\n')
    if dataString[-1] == '':
        dataString = dataString[:-1]

    dataString = [ligne.split(',') for ligne in dataString]

    labelColumn = 0

    if dataset == "PIMA":
        pass
    elif dataset == "PCS":
        # remove the index column and the two mast columns (unused)
        removeColumn(dataString, 11)
        removeColumn(dataString, 10)
        removeColumn(dataString, 0)
    elif dataset == "SPECTF":
        pass
    elif dataset == "MNIST":
        pass
    elif dataset == "GAS_SENSOR_MULTI":
        # remove index features
        for line in range(len(dataString)):
            for column in range(len(dataString[line])):
                if column != 0:
                    dataString[line][column] = dataString[line][column].split(':')[
                        1]
        pass
    elif dataset == "GAS_SENSOR":
        pass
    else:
        raise ValueError(f"unknow dataset : {dataset}")

    # Parse data
    X = []
    y = []
    line_drop = 0
    for ligne in dataString:
        y.append(label_type(ligne[labelColumn]))
        try:
            X.append([float(v)
                      for (i, v) in enumerate(ligne) if i != labelColumn])
        except ValueError:
            # There is an ambiguous value, drop the line
            y.pop()
            line_drop += 1

    # particular case
    if dataset == "MNIST":
        # Pretty important to avoid NaN during standardization
        X = [[elem/255.0 * 0.999 + 0.001 for elem in ligne] for ligne in X]

    if line_drop != 0:
        eprint(f"/!\ {line_drop} line(s) drop in LoadData {filename.split('/')[-1]}")

    txt = ""
    for (features, label) in zip(X,y):
        txt += str(label) + "," + ",".join([str(x) for x in features]) + "\n"

        
    with open(filename, "w") as fichier:
        fichier.write(txt)


import sys
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage :")
        print("\t./clean_data.py <dataSet> <fileName> <labelType>\n")
        print("\tdataSet : PCS, PIMA, SPECTF, MNIST, GAS_SENSOR_MULTI")
        print("\tlabelType : int, float")
    else:
        cleanData(sys.argv[1], sys.argv[2], sys.argv[3])


