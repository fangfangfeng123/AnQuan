"""Flask 应用入口。"""

from flask import Flask

from app.database import init_db
from app.routes.auth import auth_bp
from app.routes.orders import orders_bp
from app.routes.products import products_bp
from app.routes.upload import upload_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.register_blueprint(auth_bp)
    app.register_blueprint(orders_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(upload_bp)
    return app


app = create_app()

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, debug=False)
