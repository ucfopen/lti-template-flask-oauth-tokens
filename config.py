import settings


class Config(object):
    SQLALCHEMY_DATABASE_URI = settings.select_db('Config')
    SQLALCHEMY_TRACK_MODIFICATIONS = True


class BaseConfig(object):
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = settings.select_db('BaseConfig')
    SQLALCHEMY_TRACK_MODIFICATIONS = True


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = settings.select_db('DevelopmentConfig')
    # make the warning shut up until Flask-SQLAlchemy v3 comes out
    SQLALCHEMY_TRACK_MODIFICATIONS = True


class TestingConfig(BaseConfig):
    DEBUG = False
    TESTING = True
    SQLALCHEMY_DATABASE_URI = settings.select_db('TestingConfig')
    SQLALCHEMY_TRACK_MODIFICATIONS = True
