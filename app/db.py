import sqlite3, sys

# Creates or opens a file called mydb with a SQLite3 DB
db = sqlite3.connect('/Users/jstephan/go/src/github.com/lca1/drynx/app/Stats.db')

# Get a cursor object
cursor = db.cursor()
cursor.execute('''INSERT INTO History (queryAnswer, timest,
	operation, attribute, clientIDs) VALUES (?, ?, ?, ?, ?)''',
	(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))
db.commit()