import socket
import ssl
import json
from pathlib import Path

# Configuración - Debe escuchar en todas las interfaces
HOST = "0.0.0.0"  # Cambiado de "Banco Root CA" a 0.0.0.0
PORT = 8443
BASE_DIR = Path(__file__).parent

# Base de datos ficticia
accounts = {
    "user1": {"balance": 1500.0, "password": "clave123"},
    "user2": {"balance": 300.5, "password": "abc456"},
    "user3": {"balance": 0.0, "password": "pass789"},
    "user4 ": {"balance": 10000.0, "password": "securepass"},
    "user5": {"balance": 250.75, "password": "mypassword"},
}

def handle_request(data: str) -> dict:
    try:
        cmd = json.loads(data)
        action = cmd.get("action")
        user = cmd.get("user")
        password = cmd.get("password")

        if not all([user, password, action]):
            return {"status": "error", "message": "Faltan datos obligatorios"}

        if user not in accounts:
            return {"status": "error", "message": "Usuario no existe"}

        if accounts[user]["password"] != password:
            return {"status": "error", "message": "Contraseña incorrecta"}

        if action == "get_balance":
            return {
                "status": "success",
                "balance": accounts[user]["balance"],
                "currency": "USD"
            }

        elif action in {"deposit", "withdraw"}:
            try:
                amount = float(cmd.get("amount", 0))
                if amount <= 0.0:
                    return {"status": "error", "message": "El monto debe ser mayor que cero"}
            except (ValueError, TypeError):
                return {"status": "error", "message": "Monto inválido"}

            if action == "withdraw" and accounts[user]["balance"] < amount:
                return {"status": "error", "message": "Fondos insuficientes"}

            if action == "withdraw":
                accounts[user]["balance"] -= amount
            else:
                accounts[user]["balance"] += amount

            return {
                "status": "success",
                "balance": accounts[user]["balance"],
                "currency": "USD"
            }

        else:
            return {"status": "error", "message": "Acción no válida"}

    except json.JSONDecodeError:
        return {"status": "error", "message": "Formato JSON inválido"}
    except Exception as e:
        return {"status": "error", "message": f"Error interno: {str(e)}"}

# Iniciar el servidor TLS con autenticación mutua
def run_server():
    # Configuración TLS con autenticación mutua
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=BASE_DIR / "server-cert.pem",
        keyfile=BASE_DIR / "server-key.key"
    )
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(BASE_DIR.parent / "ca" / "ca-cert.pem")
    
    # Configuración de seguridad
    context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"Servidor escuchando en {HOST}:{PORT} (TLS 1.2+)...")
        print(f"Nombre del servidor (CN): banco.local")
        print(f"Certificado: {BASE_DIR/'server-cert.pem'}")

        with context.wrap_socket(sock, server_side=True) as secure_sock:
            while True:
                conn = None
                try:
                    conn, addr = secure_sock.accept()
                    peer_cert = conn.getpeercert()
                    cn = next(v for (k, v) in peer_cert['subject'][0] if k == 'commonName')
                    print(f"\nConexión desde: {addr} (Cliente: {cn})")
                    
                    data = conn.recv(4096).decode()
                    response = handle_request(data)
                    conn.sendall(json.dumps(response).encode())
                    
                except ssl.SSLError as e:
                    print(f"Error SSL: {str(e)}")
                except Exception as e:
                    print(f"Error: {str(e)}")
                finally:
                    if conn:
                        conn.close()

if __name__ == "__main__":
    run_server()