from flask import Flask, jsonify
from flask_smorest import Api
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate


import os
import secrets

from db import db
from blocklist import BLOCKLIST
import models

from resources.item import blp as ItemBlueprint
from resources.store import blp as StoreBlueprint
from resources.tag import blp as TagBluePrint
from resources.user import blp as UserBluePrint


app = Flask(__name__)

app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['API_TITLE'] = 'Stores REST API'
app.config['API_VERSION'] = 'v1'
app.config['OPENAPI_VERSION'] = '3.0.3'
app.config["OPENAPI_URL_PREFIX"] = "/"
app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///fdata.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)
migrate = Migrate(app, db)
api = Api(app)

app.config['JWT_SECRET_KEY'] = '376498255345275649185438246491543'
jwt = JWTManager(app)

@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    return jwt_payload['jti'] in BLOCKLIST

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return (
        jsonify(
            {'description': 'The token has been revoked',
             'error': 'token_revoked'}
        ),
        401
    )

@jwt.needs_fresh_token_loader
def token_not_fresh_callback(jwt_header, jwt_payload):
    return (
        jsonify(
            {
                "description": "The token is not fresh",
                'error': 'fresh_token_required'
            }
        ),
        401
    )

@jwt.additional_claims_loader
def add_claims_to_jwt(identity):
    pass

@jwt.expired_token_loader
def expired_tokern_callback(jwt_header, jwt_payload):
    return(
        jsonify({'message': 'The token has expired', 'error': 'token expired'}),
        401
    )

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return(
        jsonify(
            {'message': 'signature verificaition failed',
             'error': 'invalid_token'}
        ),
        401
    )

@jwt.unauthorized_loader
def missing_token_callback(error):
    return(
        jsonify(
            {
                'description': 'request does not contain access token',
                'error': 'authorization_required'
            }
        ),
        401
    )

with app.app_context():
    db.create_all()

api.register_blueprint(ItemBlueprint)
api.register_blueprint(StoreBlueprint)
api.register_blueprint(TagBluePrint)
api.register_blueprint(UserBluePrint)

if __name__ == '__main__':
    app.run(debug=True)

