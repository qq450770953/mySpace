import sqlite3
import os
from app import create_app
from app.models import User, Role

# 数据库文件路径
DB_PATH = 'app.db'

def check_database():
    try:
        # 检查数据库文件是否存在
        if not os.path.exists(DB_PATH):
            print(f"Database file not found at {DB_PATH}")
            return

        # 连接到数据库
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # 获取所有表名
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        print("\nDatabase Tables:")
        print("----------------")
        for table in tables:
            table_name = table[0]
            print(f"\nTable: {table_name}")
            print("-" * 50)

            # 获取表结构
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            print("\nColumns:")
            for col in columns:
                print(f"  {col[1]} ({col[2]})")

            # 获取行数
            cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
            count = cursor.fetchone()[0]
            print(f"\nTotal Rows: {count}")

            # 显示前5行数据（如果有）
            if count > 0:
                cursor.execute(f"SELECT * FROM {table_name} LIMIT 5;")
                rows = cursor.fetchall()
                print("\nSample Data (first 5 rows):")
                for row in rows:
                    print(f"  {row}")

        conn.close()

    except Exception as e:
        print(f"Error checking database: {str(e)}")

if __name__ == "__main__":
    app = create_app()

    with app.app_context():
        print("Users:")
        for user in User.query.all():
            print(f"- {user.username} (ID: {user.id})")
            print(f"  Roles: {[role.name for role in user.roles]}")
        
        print("\nRoles:")
        for role in Role.query.all():
            print(f"- {role.name} (ID: {role.id})")

    check_database() 