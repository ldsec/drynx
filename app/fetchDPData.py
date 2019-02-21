import sqlite3, sys

db = sqlite3.connect(sys.argv[1])
cursor = db.cursor()
tableName = sys.argv[2]

if (sys.argv[3] == 'false'):
	#The operation is not linear regression
	cursor.execute('''SELECT ''' + sys.argv[4] + ''' FROM ''' + tableName + ''' WHERE '''
	+ sys.argv[4] + ''' BETWEEN ? AND ?''', (sys.argv[5], sys.argv[6]))
	rows = cursor.fetchall()
	for row in rows:
		print(row[0])
else:
	#The operation is linear regression
	attributes = sys.argv[4].split(',')
	if (len(attributes) > 1):
		sqlQuery = '''SELECT '''
		for attribute in attributes:
			sqlQuery += attribute + ''', '''
		sqlQuery = sqlQuery[:-2]
		sqlQuery += ''' FROM ''' + tableName
	else:
		#this means we need to fetch all dimensions for all records
		sqlQuery = '''SELECT * FROM ''' + tableName	
	cursor.execute(sqlQuery)
	rows = cursor.fetchall()
	for row in rows:
		print(row)