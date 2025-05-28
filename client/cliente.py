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
        # Configuración TLS con autenticación mutua
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(BASE_DIR.parent / "ca" / "ca-cert.pem")
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Cargar certificado del cliente
        context.load_cert_chain(
            certfile=BASE_DIR / "client-cert.pem",
            keyfile=BASE_DIR / "client-key.key"
        )
        
        # Configuración de seguridad
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Conexión segura con verificación de hostname
            with context.wrap_socket(sock, server_hostname="banco.local") as secure_sock:
                secure_sock.connect((HOST, PORT))
                
                # Mostrar información del servidor
                server_cert = secure_sock.getpeercert()
                cn = next(v for (k, v) in server_cert['subject'][0] if k == 'commonName')
                print(f"🔗 Conectado a: {cn} (válido hasta: {server_cert['notAfter']})")
                
                # Enviar comando
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


# Interfaz de usuario interactiva
def interactive_client():
    print("Cliente Bancario Seguro (TLS 1.2+)")
    print("-----------------------------------")
    print(f"Conectando a: {HOST}:{PORT}")
    
    while True:
        print("\nOpciones:")
        print("1. Consultar saldo")
        print("2. Realizar deposito")
        print("3. Realizar retiro")
        print("4. Salir")
        
        choice = input("Seleccione (1/4): ").strip()
        
        if choice == "1":
            user = input("Usuario: ").strip()
            password = input("Contraseña: ").strip()
            
            print("\nAutenticando...")
            response = send_command("get_balance", user, password)
            
            if response["status"] == "success":
                print(f"\nSaldo disponible: {response['balance']} {response['currency']}")
            else:
                print(f"\nError: {response['message']}")

        elif choice == "2":
            user = input("Usuario: ").strip()
            password = input("Contraseña: ").strip()
            amount = input("Monto a depositar: ").strip()
            
            print("\nProcesando depósito...")
            response = send_command("deposit", user, password, amount)
            
            if response["status"] == "success":
                print(f"\nDepósito exitoso. Nuevo saldo: {response['balance']} {response['currency']}")
            else:
                print(f"\nError: {response['message']}")

        elif choice == "3":
            user = input("Usuario: ").strip()
            password = input("Contraseña: ").strip()
            amount = input("Monto a retirar: ").strip()
            
            print("\nProcesando retiro...")
            response = send_command("withdraw", user, password, amount)
            
            if response["status"] == "success":
                print(f"\nRetiro exitoso. Nuevo saldo: {response['balance']} {response['currency']}")
            else:
                print(f"\nError: {response['message']}")
            
                
        elif choice == "4":
            print("\nSesión finalizada")
            break
            
        else:
            print("\nOpción no válida")

if __name__ == "__main__":
    interactive_client()