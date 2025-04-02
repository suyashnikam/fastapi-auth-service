import database, models

def init_db():
    models.Base.metadata.create_all(bind=database.engine)
