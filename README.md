# 🏦 Sistema Bancario Seguro con TLS (Python)

Este proyecto implementa un sistema cliente-servidor bancario con **comunicación cifrada TLS** y **autenticación mutua (mTLS)** usando Python y sockets.

## ✅ Funcionalidades

- Autenticación de clientes mediante certificados digitales.
- Canal cifrado con **TLS 1.2+**.
- Comandos básicos: consultar saldo, depositar y retirar.
- Certificados generados con una CA propia.

---

## 🛠 Requisitos

- Python 3.7+
- OpenSSL (instalado por defecto en Linux/macOS, usar [Git Bash](https://git-scm.com/download/win) en Windows)
- Acceso a terminal con permisos de administrador para modificar el archivo `hosts`.

---

## 📁 Estructura del proyecto

/banco-tls/
│
├── client/
│ ├── client.py
│ ├── client-cert.pem
│ ├── client-key.key
│ └── ../ca/ca-cert.pem
│
├── server/
│ ├── server.py
│ ├── server-cert.pem
│ ├── server-key.key
│ └── ../ca/ca-cert.pem
│
├── ca/
│ ├── ca-cert.pem
│ └── ca-key.pem (⚠️ no incluir en producción)
│
└── README.md


---

## 🔐 Generar certificados (CA, servidor y cliente)

En una terminal (Linux/macOS o Git Bash en Windows):

```bash
mkdir -p ca client server
cd ca

# 1. Crear CA
openssl genrsa -out ca-key.pem 2048
openssl req -x509 -new -key ca-key.pem -sha256 -days 365 -out ca-cert.pem -subj "/CN=Banco Root CA"

# 2. Crear certificado del servidor
cd ../server
openssl genrsa -out server-key.key 2048
openssl req -new -key server-key.key -out server.csr -subj "/CN=banco.local"
openssl x509 -req -in server.csr -CA ../ca/ca-cert.pem -CAkey ../ca/ca-key.pem -CAcreateserial -out server-cert.pem -days 365 -sha256

# 3. Crear certificado del cliente
cd ../client
openssl genrsa -out client-key.key 2048
openssl req -new -key client-key.key -out client.csr -subj "/CN=Cliente Premium"
openssl x509 -req -in client.csr -CA ../ca/ca-cert.pem -CAkey ../ca/ca-key.pem -CAcreateserial -out client-cert.pem -days 365 -sha256

para que reconosca el host pon esto en windows
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "`n127.0.0.1 banco.local"
 En lunux o mac
echo "127.0.0.1 banco.local" | sudo tee -a /etc/hosts
