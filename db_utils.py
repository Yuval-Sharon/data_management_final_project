import sqlite3
import pandas as pd

DB_PATH = 'local_database.db'

class DbConnection:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row  # Fetch rows as dictionary-like objects
        self.cursor = self.conn.cursor()

    def close(self):
        self.conn.close()
    
    def execute_query(self, query, params=()):
        try:
            self.cursor.execute(query, params)
            self.conn.commit()
        except Exception as e:
            # Here you could choose to log the error if desired
            print("Error executing query:", e)
            raise  # re-raise if you want to handle it elsewhere

    def fetch_all(self, query, params=()) -> pd.DataFrame:
        try:
            self.cursor.execute(query, params)
            rows = self.cursor.fetchall()
            # Convert each row to a dictionary for proper DataFrame column naming
            data = [dict(row) for row in rows]
            return pd.DataFrame(data)
        except Exception as e:
            # Return a DataFrame with the error message (without full traceback)
            return pd.DataFrame({"error": [str(e)]})


query = "SELECT DISTINCT s1.bar FROM Serves s1 JOIN Serves s2 ON s1.bar = s2.bar AND s1.beer <> s2.beer WHERE s1.price < 5 AND s2.price < 5;"

db = DbConnection()
db.execute_query(query)
print(db.fetch_all(query))