import os

from flask import Flask
from flask_assets import Environment
from flask_compress import Compress
from flask_wtf import CSRFProtect

from app.assets import app_css, app_js, vendor_css, vendor_js
from config import config as Config

basedir = os.path.abspath(os.path.dirname(__file__))

csrf = CSRFProtect()
compress = Compress()


def create_app(config):
    app = Flask(__name__)
    config_name = config

    if not isinstance(config, str):
        config_name = os.getenv('FLASK_CONFIG', 'default')

    app.config.from_object(Config[config_name])
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # not using sqlalchemy event system, hence disabling it

    Config[config_name].init_app(app)

    # Set up extensions
    csrf.init_app(app)
    compress.init_app(app)

    # Register Jinja template functions
    from .utils import register_template_utils
    register_template_utils(app)

    # Set up asset pipeline
    assets_env = Environment(app)
    dirs = ['assets/styles', 'assets/scripts']
    for path in dirs:
        assets_env.append_path(os.path.join(basedir, path))
    assets_env.url_expire = True

    assets_env.register('app_css', app_css)
    assets_env.register('app_js', app_js)
    assets_env.register('vendor_css', vendor_css)
    assets_env.register('vendor_js', vendor_js)

    # Configure SSL if platform supports it
    if not app.debug and not app.testing and not app.config['SSL_DISABLE']:
        from flask_sslify import SSLify
        SSLify(app)

    # Create app blueprints
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
