import sqlite3, sys

# Creates or opens a file called mydb with a SQLite3 DB
db = sqlite3.connect('/Users/jstephan/Desktop/Client1.db')

# Get a cursor object
cursor = db.cursor()
cursor.execute('''SELECT BloodPressure FROM Records''')

rows = cursor.fetchall()
for row in rows:
	print(row[0])