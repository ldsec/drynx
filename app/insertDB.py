import sqlite3, sys

db = sqlite3.connect(sys.argv[1])
cursor = db.cursor()
cursor.execute('''INSERT INTO History (queryAnswer, timest,
	operation, attribute, clientIDs, queryMin, queryMax) VALUES (?, ?, ?, ?, ?, ?, ?)''',
	(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8]))
db.commit()