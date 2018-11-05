import sqlite3, sys

db = sqlite3.connect(sys.argv[1])
cursor = db.cursor()
cursor.execute('''SELECT ''' + sys.argv[2] + ''' FROM Records WHERE '''
	+ sys.argv[2] + ''' BETWEEN ? AND ?''', (sys.argv[3], sys.argv[4]))

rows = cursor.fetchall()
for row in rows:
	print(row[0])