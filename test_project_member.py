import sys
sys.path.append('.')

try:
    from app.models.project import ProjectMember
    print("ProjectMember import successful from app.models.project")
except ImportError as e:
    print(f"Error importing ProjectMember from app.models.project: {e}")

try:
    from app.models.projects import ProjectMember
    print("ProjectMember import successful from app.models.projects")
except ImportError as e:
    print(f"Error importing ProjectMember from app.models.projects: {e}") 