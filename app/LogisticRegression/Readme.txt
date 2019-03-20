This readme is about training and evaluating a logistic regression model trained on arrhythmia data, available as part of the Physionet Computing in Cardiology Challenge 2017 (https://physionet.org/challenge/2017).

The following steps shoud be taken:

1) Download the training set available under the "Quick Start" section at https://physionet.org/challenge/2017 (training2017.zip) and place it in the "training" directory.

2) Run the "QRSDetector.py" python script to parse the training data and generate as output the csv file "Dataset_withFeatures.csv".

3) Run the "Predict.py" script using the following command: python Predict.py `nbrIterations`,
where nbrIterations is the number of times over which the accuracy of the logistic regression model should be averaged, i.e., the number of times to train and evaluate the logistic regression model.

4) Read the average measured accuracy on the terminal.