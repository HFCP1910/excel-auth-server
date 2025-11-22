from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------------------------------------
# CONFIG: CADENA DE CONEXIÓN A POSTGRES EN RENDER
# -------------------------------------------------------
DB_URL = "postgresql://excel_auth_db_user:TU_CONTRASEÑA@dpg-d4gv6jjuibrs73d9g890-a.oregon-postgres.render.com/excel_auth_db"

app = FastAPI()


# -------------------------------------------------------
# FUNCIÓN PARA CONECTAR A POSTGRES
# -------------------------------------------------------
def get_conn():
    return psycopg2.connect(DB_URL, cursor_factory=RealDictCursor)


# -------------------------------------------------------
# CREAR TABLA SI NO EXISTE
# -------------------------------------------------------
def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    conn.commit()

    # Usuario administrador por defecto
    cur.execute("SELECT * FROM users WHERE username='jefe'")
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            ("jefe", generate_password_hash("admin123"), "admin")
        )
        conn.commit()

    conn.close()


# -------------------------------------------------------
# MODELOS JSON
# -------------------------------------------------------
class LoginModel(BaseModel):
    username: str
    password: str


class AddUserModel(BaseModel):
    username: str
    password: str
    role: str


class ChangePasswordModel(BaseModel):
    username: str
    old_password: str
    new_password: str


# -------------------------------------------------------
# RUTA DE PRUEBA
# -------------------------------------------------------
@app.get("/")
def root():
    return {"status": "ok", "msg": "Servidor Excel Auth funcionando"}


# -------------------------------------------------------
# LOGIN (USADO POR EXCEL)
# -------------------------------------------------------
@app.post("/login")
def login(data: LoginModel):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT username, password_hash, role FROM users WHERE username=%s", 
                (data.username,))
    row = cur.fetchone()

    conn.close()

    if not row or not check_password_hash(row["password_hash"], data.password):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    return {"status": "ok", "role": row["role"]}


# -------------------------------------------------------
# AÑADIR USUARIO (solo admin)
# -------------------------------------------------------
@app.post("/add_user")
def add_user(data: AddUserModel):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT username FROM users WHERE username=%s", (data.username,))
    if cur.fetchone():
        raise HTTPException(status_code=400, detail="El usuario ya existe")

    cur.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
        (data.username, generate_password_hash(data.password), data.role),
    )
    conn.commit()
    conn.close()

    return {"status": "ok", "msg": "Usuario agregado correctamente"}


# -------------------------------------------------------
# CAMBIO DE CONTRASEÑA (usuario normal)
# -------------------------------------------------------
@app.post("/change_password")
def change_password(data: ChangePasswordModel):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT username, password_hash FROM users WHERE username=%s",
                (data.username,))
    row = cur.fetchone()

    if not row or not check_password_hash(row["password_hash"], data.old_password):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    cur.execute("UPDATE users SET password_hash=%s WHERE username=%s",
                (generate_password_hash(data.new_password), data.username))

    conn.commit()
    conn.close()

    return {"status": "ok", "msg": "Contraseña actualizada"}


# -------------------------------------------------------
# INICIALIZAR BASE DE DATOS AUTOMÁTICAMENTE
# -------------------------------------------------------
init_db()
