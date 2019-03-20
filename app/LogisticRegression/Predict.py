import pandas as pd, numpy as np
import csv, random, sys
from sklearn.linear_model import LogisticRegression
from sklearn.cross_validation import cross_val_score

Normal = []
Arrhythmia = []
nbrIterations = int(sys.argv[1])

#Part 1: Randomly generate nbrIterations (e.g., 100) different datasets by sampling the same number of arrhythmia and normal samples

#Parse the training dataset, and populate the two lists Normal and Arrhythmia
with open('datasets/Dataset_withFeatures.csv', mode='r') as csv_file:
	csv_reader = csv.reader(csv_file)
	for row in csv_reader:
		if (row[len(row) - 1] == 'N'):
			Normal.append(row[1] + "," + row[2] + "," + row[3] + "," + row[4] + "," + row[5] + "," + row[6]
				+ "," + row[7] + "," + row[8] + "," + row[9] + ",0")
		else:
			Arrhythmia.append(row[1] + "," + row[2] + "," + row[3] + "," + row[4] + "," + row[5] + "," + row[6]
				+ "," + row[7] + "," + row[8] + "," + row[9] + ",1")

requiredSize = min(len(Arrhythmia), len(Normal))
for i in range(nbrIterations):
	#Sample requiredSize number of samples of each label () in order to mitigate data skewness
	#and have a balanced distribution
	NormalReduced = random.sample(Normal, requiredSize)
	ArrhythmiaReduced = random.sample(Arrhythmia, requiredSize)
	#Join the two groups of samples and shuffle them (before feeding them as
	#training data to the logistic regression model)
	totalData = NormalReduced + ArrhythmiaReduced
	random.shuffle(totalData)
	#Write the training samples on csv files
	with open('datasets/finalShuffledDataset_' + str(i) + '.csv', 'w') as csvfile:
		writer = csv.writer(csvfile)
		for row in totalData:
			writer.writerow(row.split(","))

#Part 2: Predict
#Train and evaluate a logistic regression model nbrIterations times (over the previously generated datasets)
#Output the average accuracy

avg_score = 0
for i in range(nbrIterations):
	df = pd.read_csv('datasets/finalShuffledDataset_' + str(i) + '.csv')	
	X = df.iloc[:, 0:8]
	y = df.iloc[:, 9]
	clf = LogisticRegression(random_state=random.randint(0, 200), solver='lbfgs', max_iter=100, C=1.0)
	avg_score += cross_val_score(clf, X, y, cv=10, scoring='accuracy').mean()
avg_score /= nbrIterations
print("The accuracy of the logistic regression model is " + str(avg_score))