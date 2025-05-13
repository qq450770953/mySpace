from flask import Blueprint, request, jsonify, render_template, redirect, url_for, make_response, abort, session, g, current_app, flash
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from werkzeug.utils import secure_filename
from app.models.project import Project
from app.models.auth import User, UserProject
from app.models.task import Task
from app.utils.decorators import permission_required
from app.utils.constants import PERMISSION_VIEW_PROJECT, PERMISSION_MANAGE_PROJECT, PERMISSION_CREATE_PROJECT
from app import db, csrf, jwt
from datetime import datetime, timedelta
import json
import os
import logging
import uuid

# 创建蓝图
project_bp = Blueprint('projects', __name__, url_prefix='/projects')

# 设置日志
logger = logging.getLogger(__name__)

@project_bp.errorhandler(400)
def handle_csrf_error(e):
    # 检查是否是CSRF错误
    if 'CSRF' in str(e):
        logger.warning(f"CSRF验证失败: {str(e)}")
        return jsonify({
            'error': 'CSRF验证失败，请刷新页面后重试',
            'code': 'csrf_error'
        }), 400
    
    # 处理其他400错误
    logger.warning(f"请求错误: {str(e)}")
    return jsonify({
        'error': f'请求错误: {str(e)}',
        'code': 'bad_request'
    }), 400

@project_bp.errorhandler(404)
def handle_not_found(e):
    logger.warning(f"资源未找到: {str(e)}")
    return jsonify({
        'error': '请求的资源不存在',
        'code': 'not_found'
    }), 404

# 添加所有其他函数...

@project_bp.errorhandler(500)
def handle_internal_error(e):
    """处理内部服务器错误"""
    logger.error(f"内部服务器错误: {str(e)}")
    return render_template('error.html', error='服务器内部错误，请联系管理员'), 500 