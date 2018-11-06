import sqlite3, sys

db = sqlite3.connect(sys.argv[1])
cursor = db.cursor()

if (sys.argv[2] == 'false'):
	#The operation is not linear regression
	cursor.execute('''SELECT ''' + sys.argv[3] + ''' FROM Records WHERE '''
	+ sys.argv[3] + ''' BETWEEN ? AND ?''', (sys.argv[4], sys.argv[5]))
	rows = cursor.fetchall()
	for row in rows:
		print(row[0])
else:
	#The operation is linear regression
	attributes = sys.argv[3].split(',')
	sqlQuery = '''SELECT '''
	for attribute in attributes:
		sqlQuery += attribute + ''', '''
	sqlQuery = sqlQuery[:-2]
	sqlQuery += ''' FROM Records'''
	cursor.execute(sqlQuery)
	rows = cursor.fetchall()
	for row in rows:
		print(row)