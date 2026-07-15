import sqlite3

def initialize_database():

    #connect to the database
    #opens the db if it does exist, creates it if it doesn't
    connection = sqlite3.connect("bacnet.db")

    #enable foreign keys
    connection.execute("PRAGMA foreign_keys = ON")

    #create the capture table
    connection.execute("""
        CREATE TABLE IF NOT EXISTS captures (
            capture_id INTEGER PRIMARY KEY,
            filename TEXT NOT NULL,
            imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            capture_start TEXT,
            capture_end TEXT
        )
    """)

    connection.commit()

    return connection

def insert_capture(cursor, filename, capture_start, capture_end):

    try:
        cursor.execute(
                        """
                        INSERT INTO captures (
                        filename, 
                        capture_start,
                        capture_end
                        )
                        VALUES (?, ?, ?)
                        """,
                        (filename, 
                         capture_start,
                         capture_end
                        )
                    )
        
    except sqlite3.Error as error:
        print(f"Capture insertion error: {error}")
        return None