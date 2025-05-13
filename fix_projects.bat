@echo off
echo Creating a new clean version of projects.py...

echo from flask import Blueprint, request, jsonify, render_template, redirect, url_for, make_response > app/routes/projects_clean.py
echo from flask import current_app >> app/routes/projects_clean.py
echo import pytz >> app/routes/projects_clean.py
echo from app import csrf  # 导入CSRFProtect实例 >> app/routes/projects_clean.py
echo from app.models import Project, User, Task, TeamMember >> app/routes/projects_clean.py
echo from app.models.auth import User >> app/routes/projects_clean.py
echo from app import db >> app/routes/projects_clean.py
echo from datetime import datetime >> app/routes/projects_clean.py
echo import logging >> app/routes/projects_clean.py
echo from sqlalchemy import or_ >> app/routes/projects_clean.py
echo from flask import current_app >> app/routes/projects_clean.py
echo import pytz >> app/routes/projects_clean.py
echo from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt >> app/routes/projects_clean.py
echo import json >> app/routes/projects_clean.py
echo # 导入权限相关的工具 >> app/routes/projects_clean.py
echo from app.utils.permissions import ( >> app/routes/projects_clean.py
echo     permission_required,  >> app/routes/projects_clean.py
echo     can_manage_project,  >> app/routes/projects_clean.py
echo     PERMISSION_MANAGE_ALL_PROJECTS, >> app/routes/projects_clean.py
echo     PERMISSION_MANAGE_PROJECT, >> app/routes/projects_clean.py
echo     PERMISSION_VIEW_PROJECT, >> app/routes/projects_clean.py
echo     PERMISSION_CREATE_PROJECT, >> app/routes/projects_clean.py
echo     ROLE_ADMIN, >> app/routes/projects_clean.py
echo     ROLE_PROJECT_MANAGER >> app/routes/projects_clean.py
echo ) >> app/routes/projects_clean.py
echo. >> app/routes/projects_clean.py
echo project_bp = Blueprint('projects', __name__) >> app/routes/projects_clean.py
echo logger = logging.getLogger(__name__) >> app/routes/projects_clean.py
echo. >> app/routes/projects_clean.py

echo Moving the new clean file to replace the original...
rename app\routes\projects.py projects.py.old
rename app\routes\projects_clean.py projects.py

echo Fixing has been completed.

echo You should now try to complete fixing the project by adding all the missing routes manually. 