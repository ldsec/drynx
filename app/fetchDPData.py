import sqlite3, sys

db = sqlite3.connect(sys.argv[1])
cursor = db.cursor()
cursor.execute('''SELECT BloodPressure FROM Records WHERE BloodPressure
	BETWEEN ? AND ?''', (sys.argv[2], sys.argv[3]))

rows = cursor.fetchall()
for row in rows:
	print(row[0])