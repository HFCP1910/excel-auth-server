# app.py
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

DB = "users.db"
app = Flask(__name__)

# -----------------------------
#  INICIALIZACIÓN DE LA BASE DE DATOS
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    # Crea tabla si no existe
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            allowed_sheets TEXT DEFAULT ''
        )
    """)

    # Insertar usuarios demo si no existen
    c.execute("SELECT COUNT(*) FROM users")
    count = c.fetchone()[0]

    if count == 0:
        c.execute("INSERT INTO users (username, password_hash, role, allowed_sheets) VALUES (?, ?, ?, ?)",
                  ("jefe", generate_password_hash("admin123"), "admin", ""))

        c.execute("INSERT INTO users (username, password_hash, role, allowed_sheets) VALUES (?, ?, ?, ?)",
                  ("ana", generate_password_hash("asist123"), "asistente", "Inicio,Datos"))

        conn.commit()

    conn.close()

# Ejecutar al iniciar
init_db()

# -----------------------------
#  FUNCIONES AUXILIARES
# -----------------------------
def get_user(username):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT username, password_hash, role, allowed_sheets FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row


# -----------------------------
#  ENDPOINTS
# -----------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    user = data.get("usuario")
    pwd = data.get("password")

    row = get_user(user)
    if row and check_password_hash(row[1], pwd):
        return jsonify({"status": "ok", "rol": row[2], "allowed_sheets": row[3]})
    else:
        return jsonify({"status": "error"}), 401


@app.route("/change_password", methods=["POST"])
def change_password():
    data = request.get_json(force=True)
    user = data.get("usuario")
    old = data.get("vieja") or data.get("old_password")
    new = data.get("nueva") or data.get("new_password")

    row = get_user(user)
    if not row or not check_password_hash(row[1], old):
        return jsonify({"status": "error", "msg": "credenciales invalidas"}), 401

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ? WHERE username = ?",
              (generate_password_hash(new), user))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


@app.route("/admin_change_password", methods=["POST"])
def admin_change_password():
    data = request.get_json(force=True)
    admin_user = data.get("admin_usuario")
    admin_pass = data.get("admin_clave")
    target_user = data.get("usuario_objetivo")
    new_pass = data.get("nueva_clave")

    row = get_user(admin_user)
    if not row or not check_password_hash(row[1], admin_pass) or row[2] != "admin":
        return jsonify({"status": "error", "msg": "Solo el administrador puede cambiar contraseñas."}), 403

    row2 = get_user(target_user)
    if not row2:
        return jsonify({"status": "error", "msg": "Usuario no encontrado."}), 404

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ? WHERE username = ?",
              (generate_password_hash(new_pass), target_user))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "msg": f"Contraseña de {target_user} actualizada correctamente."})


@app.route("/create_user", methods=["POST"])
def create_user():
    data = request.get_json(force=True)
    admin_user = data.get("admin_usuario")
    admin_pass = data.get("admin_clave")
    new_user = data.get("nuevo_usuario")
    new_pass = data.get("nueva_clave")
    new_role = data.get("rol")
    allowed_sheets = data.get("allowed_sheets", "")

    row = get_user(admin_user)
    if not row or not check_password_hash(row[1], admin_pass) or row[2] != "admin":
        return jsonify({"status": "error", "msg": "Solo el administrador puede crear usuarios."}), 403

    if get_user(new_user):
        return jsonify({"status": "error", "msg": "El usuario ya existe."}), 400

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("INSERT INTO users(username, password_hash, role, allowed_sheets) VALUES (?, ?, ?, ?)",
              (new_user, generate_password_hash(new_pass), new_role, allowed_sheets))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "msg": f"Usuario {new_user} creado correctamente."})


@app.route("/set_user_sheets", methods=["POST"])
def set_user_sheets():
    data = request.get_json(force=True)
    admin_user = data.get("admin_usuario")
    admin_pass = data.get("admin_clave")
    target_user = data.get("usuario_objetivo")
    allowed_sheets = data.get("allowed_sheets", "")

    row = get_user(admin_user)
    if not row or not check_password_hash(row[1], admin_pass) or row[2] != "admin":
        return jsonify({"status": "error", "msg": "Solo el administrador puede actualizar permisos."}), 403

    row2 = get_user(target_user)
    if not row2:
        return jsonify({"status": "error", "msg": "Usuario no encontrado."}), 404

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE users SET allowed_sheets = ? WHERE username = ?", (allowed_sheets, target_user))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "msg": f"Hojas permitidas de {target_user} actualizadas."})


# -----------------------------
#  PRODUCCIÓN EN RENDER
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

