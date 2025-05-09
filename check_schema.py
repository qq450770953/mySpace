from app import create_app, db
from sqlalchemy import text

app = create_app()

with app.app_context():
    result = db.session.execute(text("PRAGMA table_info(tasks)"))
    columns = result.fetchall()
    print("\nTasks table schema:")
    print("------------------")
    for col in columns:
        print(f"Column: {col[1]}, Type: {col[2]}, NotNull: {col[3]}, DefaultValue: {col[4]}") 