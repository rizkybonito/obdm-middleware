import os
from flask import Flask, jsonify, make_response
from flask_cors import CORS
from werkzeug.exceptions import Unauthorized, Forbidden, InternalServerError
from .config import DevelopmentConfig
from .routes import api_bp

def create_app(config_class=DevelopmentConfig):
    app = Flask(__name__)
    app.config.from_object(config_class)
    CORS(app, 
         supports_credentials=True, 
         origins=app.config['CORS_ORIGINS'], 
         allow_headers=["Content-Type", "Authorization"])
    
    app.register_blueprint(api_bp)

    @app.errorhandler(Unauthorized)
    def handle_unauthorized(e):
        return make_response(jsonify({"message": str(e)}), 401)

    @app.errorhandler(Forbidden)
    def handle_forbidden(e):
        return make_response(jsonify({"message": str(e)}), 403)

    @app.errorhandler(InternalServerError)
    def handle_internal_server_error(e):
        return make_response(jsonify({"message": str(e)}), 500)

    @app.errorhandler(404)
    def resource_not_found(e):
        return make_response(jsonify({'message': 'The requested resource was not found'}), 404)
    
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=app.config['DEBUG'])