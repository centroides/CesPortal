from flask import g
import sqlite3

def connect_to_database():
    sql = sqlite3.connect('C:/Users/CENTROID/Documents/ces_india/centro.db')
    sql.row_factory = sqlite3.Row
    return sql

def get_database():
    if not hasattr(g, 'centro_db'):
        g.centro_db = connect_to_database()
    
    return g.centro_db


