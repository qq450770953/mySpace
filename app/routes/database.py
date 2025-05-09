from flask import Blueprint, render_template, jsonify
from flask_jwt_extended import jwt_required
from app.extensions import db
from sqlalchemy import inspect

bp = Blueprint('database', __name__)

@bp.route('/tables')
@jwt_required()
def show_tables():
    """显示所有数据库表"""
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    table_info = []
    
    for table_name in tables:
        columns = inspector.get_columns(table_name)
        table_info.append({
            'name': table_name,
            'columns': [{'name': col['name'], 'type': str(col['type'])} for col in columns]
        })
    
    return render_template('database/tables.html', tables=table_info)

@bp.route('/api/tables')
@jwt_required()
def get_tables():
    """获取所有数据库表的API"""
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    table_info = []
    
    for table_name in tables:
        columns = inspector.get_columns(table_name)
        table_info.append({
            'name': table_name,
            'columns': [{'name': col['name'], 'type': str(col['type'])} for col in columns]
        })
    
    return jsonify(table_info) 