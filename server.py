from fastapi import FastAPI, HTTPException
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI()

DB_URL = "postgresql://excel_auth_db_user:contraseña@dpg-d4gv6jjuibrs73d9g890-a.oregon-postgres.render.com/excel_auth_db"


def get_conn():
    return psycopg2.connect(DB_URL, cursor_factory=RealDictCursor)


@app.get("/")
def root():
    return {"status": "ok", "msg": "Servidor Excel Auth funcionando"}


@app.post("/login")
def login(username: str, password: str):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
    user = cur.fetchone()

    cur.close()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    return {"status": "ok", "role": user["role"]}


@app.post("/add_user")
def add_user(username: str, password: str, role: str):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", 
                (username, password, role))
    conn.commit()

    cur.close()
    conn.close()

    return {"status": "ok", "msg": "Usuario agregado"}
