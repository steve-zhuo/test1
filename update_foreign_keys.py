from app import db
from app import Review

# Create a backup of the existing reviews
db.session.execute("CREATE TABLE review_backup AS SELECT * FROM review")

# Drop the old review table
db.session.execute("DROP TABLE review")

# Create new review table with proper foreign key constraints
db.session.execute("""
CREATE TABLE review (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    rating INTEGER NOT NULL,
    author_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES service(id) ON DELETE CASCADE
)
""")

# Copy data back from backup
db.session.execute("INSERT INTO review SELECT * FROM review_backup")

# Drop the backup table
db.session.execute("DROP TABLE review_backup")

# Commit the changes
db.session.commit()

print("Database schema updated successfully!")
