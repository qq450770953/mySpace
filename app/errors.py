from flask import jsonify
from werkzeug.exceptions import HTTPException

def register_error_handlers(app):
    """注册错误处理器"""
    
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({
            'error': 'Bad Request',
            'message': str(e)
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({
            'error': 'Unauthorized',
            'message': str(e)
        }), 401
    
    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({
            'error': 'Forbidden',
            'message': str(e)
        }), 403
    
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({
            'error': 'Not Found',
            'message': str(e)
        }), 404
    
    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({
            'error': 'Method Not Allowed',
            'message': str(e)
        }), 405
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return jsonify({
            'error': 'Internal Server Error',
            'message': str(e)
        }), 500
    
    @app.errorhandler(Exception)
    def handle_exception(e):
        # 处理所有未捕获的异常
        if isinstance(e, HTTPException):
            return e
        
        app.logger.error(f'Unhandled exception: {str(e)}')
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred'
        }), 500 