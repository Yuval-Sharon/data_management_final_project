import sqlite3

# Connect to the SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('local_database.db')
cursor = conn.cursor()

# Create the Likes table
cursor.execute('''
CREATE TABLE IF NOT EXISTS Likes (
    drinker TEXT,
    beer TEXT
)
''')

# Create the Frequents table
cursor.execute('''
CREATE TABLE IF NOT EXISTS Frequents (
    drinker TEXT,
    bar TEXT
)
''')

# Create the Serves table
cursor.execute('''
CREATE TABLE IF NOT EXISTS Serves (
    bar TEXT,
    beer TEXT,
    price REAL
)
''')

# Insert fake data into the Likes table.
# Note: The entry for ('Alice', 'NonExistingBeer') will make Query4 return an extra beer 
# in the user query compared to the q_star query.
cursor.executemany('''
INSERT INTO Likes (drinker, beer) VALUES (?, ?)
''', [
    ('Alice', 'IPA'),
    ('Alice', 'Blonde Ale'),
    ('Alice', 'NonExistingBeer'),  # Extra entry to differentiate Query4 results
    ('Bob', 'Stout'),
    ('Bob', 'Brown Ale'),
    ('Charlie', 'Lager'),
    ('David', 'Pilsner'),
    ('Eve', 'Porter'),
    ('Frank', 'Ale'),
    ('Grace', 'Wheat'),
    ('Hannah', 'Saison'),
    ('Ivy', 'Pale Ale'),
    ('Jack', 'Amber Ale'),
    # Add more entries as needed
])

# Insert fake data into the Frequents table
cursor.executemany('''
INSERT INTO Frequents (drinker, bar) VALUES (?, ?)
''', [
    ('Alice', 'Bar One'),
    ('Alice', 'Bar Eleven'),
    ('Bob', 'Bar Two'),
    ('Bob', 'Bar Twelve'),
    ('Charlie', 'Bar Three'),
    ('David', 'Bar Four'),
    ('Eve', 'Bar Five'),
    ('Frank', 'Bar Six'),
    ('Grace', 'Bar Seven'),
    ('Hannah', 'Bar Eight'),
    ('Ivy', 'Bar Nine'),
    ('Jack', 'Bar Ten'),
    # Add more entries as needed
])

# Insert fake data into the Serves table
cursor.executemany('''
INSERT INTO Serves (bar, beer, price) VALUES (?, ?, ?)
''', [
    ('Bar One', 'IPA', 5.0),
    ('Bar Two', 'Stout', 6.0),
    ('Bar Three', 'Lager', 4.5),
    ('Bar Four', 'Pilsner', 5.5),
    ('Bar Five', 'Porter', 6.5),
    ('Bar Six', 'Ale', 4.0),
    ('Bar Seven', 'Wheat', 5.0),
    ('Bar Eight', 'Saison', 7.0),
    ('Bar Nine', 'Pale Ale', 5.5),
    ('Bar Ten', 'Amber Ale', 6.0),
    ('Bar Eleven', 'Blonde Ale', 4.0),
    ('Bar Twelve', 'Brown Ale', 4.5),
    ('Bar Twelve', 'Lager', 4.0),
    # Add more entries as needed
])

# Commit the changes and close the connection
conn.commit()
conn.close()

print("Database and tables created with modified sample data.")
