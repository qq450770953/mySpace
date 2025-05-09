from app import create_app, db
from sqlalchemy import text

app = create_app()

with app.app_context():
    # Check if progress column exists
    result = db.session.execute(text("PRAGMA table_info(tasks)"))
    columns = [row[1] for row in result]
    
    if 'progress' not in columns:
        print("Adding progress column to tasks table...")
        db.session.execute(text('ALTER TABLE tasks ADD COLUMN progress INTEGER NOT NULL DEFAULT 0;'))
        db.session.commit()
        print("Progress column added successfully!")
    else:
        print("Progress column already exists in tasks table.") 