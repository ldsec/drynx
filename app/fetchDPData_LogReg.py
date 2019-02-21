import sqlite3, sys

db = sqlite3.connect(sys.argv[1])
cursor = db.cursor()

sqlQuery = '''SELECT average, squareAvg, variance, standardDeviation, median, avgSquared, medianSquared,
MeanAvgSquMedSqu, modeSquared, Label FROM Data'''
cursor.execute(sqlQuery)
rows = cursor.fetchall()
for row in rows:
	print(row)
