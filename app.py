from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

DB = "users.db"
app = Flask(__name__)

def init_db():
    if not os.path.exists(DB):
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("""CREATE TABLE users (
                        username TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL
                    )""")
        # Usuarios de prueba
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  ("jefe", generate_password_hash("admin123"), "admin"))
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  ("ana", generate_password_hash("asist123"), "asistente"))
        conn.commit()
        conn.close()

def get_user(username):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT username, password_hash, role FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    user = data.get("usuario")
    pwd = data.get("password")
    row = get_user(user)
    if row and check_password_hash(row[1], pwd):
        return jsonify({"status": "ok", "rol": row[2]})
    else:
        return jsonify({"status": "error"}), 401

@app.route("/change_password", methods=["POST"])
def change_password():
    data = request.get_json(force=True)
    user = data.get("usuario")
    old = data.get("vieja")
    new = data.get("nueva")
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

    # Verificar que quien hace la solicitud es un administrador válido
    row = get_user(admin_user)
    if not row or not check_password_hash(row[1], admin_pass) or row[2] != "admin":
        return jsonify({"status": "error", "msg": "Solo el administrador puede cambiar contraseñas."}), 403

    # Verificar que el usuario a modificar exista
    row2 = get_user(target_user)
    if not row2:
        return jsonify({"status": "error", "msg": "Usuario no encontrado."}), 404

    # Cambiar la contraseña del usuario objetivo
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ? WHERE username = ?",
              (generate_password_hash(new_pass), target_user))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "msg": f"Contraseña de {target_user} actualizada correctamente."})


# 👇 ESTA ES LA PARTE MODIFICADA
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))  # Usa el puerto asignado por Render
    app.run(host="0.0.0.0", port=port)
