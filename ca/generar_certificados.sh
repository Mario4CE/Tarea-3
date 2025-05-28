#!/bin/bash

# Generar CA
openssl req -x509 -newkey rsa:4096 -keyout ca-key.key -out ca-cert.pem -days 365 -nodes -subj "/CN=Banco Root Ca"

# Servidor: Generar clave + CSR
openssl req -newkey rsa:4096 -keyout ../server/server-key.key -out server-req.pem -nodes -subj "/CN=banco.local"

# Firmar certificado servidor
openssl x509 -req -in server-req.pem -CA ca-cert.pem -CAkey ca-key.key -CAcreateserial -out ../server/server-cert.pem -days 365

# Cliente: Generar clave + CSR (opcional)
openssl req -newkey rsa:4096 -keyout ../client/client-key.key -out client-req.pem -nodes -subj "/CN=Cliente Premium"

# Firmar certificado cliente
openssl x509 -req -in client-req.pem -CA ca-cert.pem -CAkey ca-key.key -CAcreateserial -out ../client/client-cert.pem -days 365

echo "✅ Certificados generados en:"
echo "CA: ca/{ca-key.key,ca-cert.pem}"
echo "Servidor: server/{server-key.key,server-cert.pem}"
echo "Cliente: client/{client-key.key,client-cert.pem}"