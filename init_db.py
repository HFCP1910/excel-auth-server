import sqlite3
import bcrypt

conn = sqlite3.connect("users.db")
c = conn.cursor()

# Eliminar tabla anterior (si existe)
c.execute("DROP TABLE IF EXISTS users")

# Crear tabla nueva con todas las columnas
c.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    allowed_sheets TEXT NOT NULL
)
""")

# Crear usuarios iniciales
users = [
    ("jefe", "admin123", "admin", "Hoja1,Hoja2,Hoja3"),
    ("empleado", "empleado123", "empleado", "Hoja1")
]

for username, password, role, sheets in users:
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    c.execute("INSERT INTO users (username, password_hash, role, allowed_sheets) VALUES (?, ?, ?, ?)",
              (username, hashed, role, sheets))

conn.commit()
conn.close()

print("Base de datos creada correctamente.")
