#!/usr/bin/python3
import sys


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def remove_column(tab, index):
    for i in range(len(tab)):
        del tab[i][index]


"""
@brief cleanData clean some specific datasets
@param dataset string, available datasets are : PCS, PIMA, SPECTF, MNIST, GAS_SENSOR_MULTI
@param filename string, the filename of dataset which will be cleaned
"""


def clean_data(dataset, filename, label_type):
    
    if label_type == "int":
        label_type = int
    elif label_type == "float":
        label_type = float
    else:
        raise(ValueError(f"Unknow type {label_type}"))

    dataset = dataset.upper()

    with open(filename, "r") as fichier:
        data_string = fichier.read()

    data_string = data_string.split('\n')
    if data_string[-1] == '':
        data_string = data_string[:-1]

    data_string = [ligne.split(',') for ligne in data_string]

    label_column = 0

    if dataset == "PIMA":
        pass
    elif dataset == "PCS":
        # remove the index column and the two mast columns (unused)
        remove_column(data_string, 11)
        remove_column(data_string, 10)
        remove_column(data_string, 0)
    elif dataset == "SPECTF":
        pass
    elif dataset == "MNIST":
        pass
    elif dataset == "GAS_SENSOR_MULTI":
        # remove index features
        for line in range(len(data_string)):
            for column in range(len(data_string[line])):
                if column != 0:
                    data_string[line][column] = data_string[line][column].split(':')[
                        1]
        pass
    elif dataset == "GAS_SENSOR":
        pass
    else:
        raise ValueError(f"unknow dataset : {dataset}")

    # Parse data
    x = []
    y = []
    line_drop = 0
    for ligne in data_string:
        y.append(label_type(ligne[label_column]))
        try:
            x.append([float(v)
                      for (i, v) in enumerate(ligne) if i != label_column])
        except ValueError:
            # There is an ambiguous value, drop the line
            y.pop()
            line_drop += 1

    # particular case
    if dataset == "MNIST":
        # Pretty important to avoid NaN during standardization
        x = [[elem/255.0 * 0.999 + 0.001 for elem in ligne] for ligne in x]

    if line_drop != 0:
        eprint(f"/! {line_drop} line(s) drop in LoadData {filename.split('/')[-1]}")

    txt = ""
    for (features, label) in zip(x, y):
        txt += str(label) + "," + ",".join([str(x) for x in features]) + "\n"

    with open(filename, "w") as fichier:
        fichier.write(txt)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage :")
        print("\t./clean_data.py <dataSet> <fileName> <labelType>\n")
        print("\tdataSet : PCS, PIMA, SPECTF, MNIST, GAS_SENSOR_MULTI")
        print("\tlabelType : int, float")
    else:
        clean_data(sys.argv[1], sys.argv[2], sys.argv[3])
