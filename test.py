import sqlite3

# Step 1: Connect to the database (or create it if it doesn't exist)
connection = sqlite3.connect("C:\\Users\\jacob\\Documents\\bracket\\instance\\tournament.db")

# Step 2: Create a cursor object
cursor = connection.cursor()

# Step 3: Execute a SELECT query
cursor.execute("SHOW TABLES")
#cursor.execute("SELECT * FROM matches")

# Step 4: Fetch and process the results
rows = cursor.fetchall()
for row in rows:
    print(row)

# Step 5: Close the connection
connection.close()
