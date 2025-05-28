import socket
import ssl
import json
from pathlib import Path

# Configuración - IMPORTANTE: Usar el hostname del SERVIDOR
HOST = "banco.local"  # Cambiado de "Cliente Priemium" a "banco.local"
PORT = 8443
BASE_DIR = Path(__file__).parent

def send_command(action: str, user: str = None, password: str = None, amount: str = None) -> dict:
    try:
        # Configurar contexto TLS
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(CA_CERT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)

        # Deshabilitar protocolos inseguros
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as secure_sock:
                secure_sock.connect((HOST, PORT))

                # Mostrar información del certificado del servidor
                server_cert = secure_sock.getpeercert()
                cn = next(v for (k, v) in server_cert['subject'][0] if k == 'commonName')
                print(f"Conectado a: {cn} (válido hasta: {server_cert['notAfter']})")

                # Armar el comando
                command = {
                    "action": action,
                    "user": user,
                    "password": password
                }
                if amount is not None:
                    command["amount"] = amount

                secure_sock.sendall(json.dumps(command).encode('utf-8'))

                # Recibir respuesta completa (hasta 64 KB)
                response = secure_sock.recv(65536).decode('utf-8')
                return json.loads(response)

    except ssl.SSLError as e:
        return {"status": "error", "message": f"Error SSL: {e}"}
    except Exception as e:
        return {"status": "error", "message": f"Error de conexión: {str(e)}"}

# Interfaz interactiva
def interactive_client():
    print("Cliente Bancario Seguro (TLS 1.2+)")
    print("-----------------------------------")
    print(f"Conectando a: {HOST}:{PORT}")
    
    while True:
        print("\nOpciones:")
        print("1. Consultar saldo")
        print("2. Realizar depósito")
        print("3. Realizar retiro")
        print("4. Salir")

        choice = input("Seleccione (1-4): ").strip()

        if choice not in {"1", "2", "3", "4"}:
            print("Opción no válida.")
            continue

        if choice == "4":
            print("\nSesión finalizada.")
            break

        user = input("Usuario: ").strip()
        password = input("Contraseña: ").strip()

        if not user or not password:
            print("Usuario y contraseña son requeridos.")
            continue

        if choice in {"2", "3"}:
            amount = input("Monto: ").strip()
            if not amount.replace('.', '', 1).isdigit():
                print("⚠️ Monto inválido.")
                continue

            action = "deposit" if choice == "2" else "withdraw"
            response = send_command(action, user, password, amount)
        else:
            response = send_command("get_balance", user, password)

        if response["status"] == "success":
            if "balance" in response:
                print(f"\nOperación exitosa. Saldo: {response['balance']} {response.get('currency', '')}")
            else:
                print("\nOperación completada.")
        else:
            print(f"\nError: {response['message']}")

if __name__ == "__main__":
    interactive_client()