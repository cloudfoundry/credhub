#!/bin/bash

generate_grpc_certs() {
  echo "Generating gPRC Certs"

  rm -rf grpc-certs
  mkdir -p grpc-certs
  pushd grpc-certs
  openssl req \
      -x509 \
      -newkey rsa:2048 \
      -days 365 \
      -sha256 \
      -nodes \
      -subj "/CN=localhost" \
      -keyout grpc_ca_private.pem \
      -out grpc_ca_cert.pem

  openssl genrsa -out grpc_server_key.pem 2048
  openssl req -new -sha256 -key grpc_server_key.pem -subj "/CN=localhost" -out grpc_server.csr
  openssl x509 -req -in grpc_server.csr -sha384 -CA grpc_ca_cert.pem -CAkey grpc_ca_private.pem \
      -CAcreateserial -out grpc_server_cert.pem

  openssl genrsa -out grpc_client_key_pkcs1.pem 2048
  openssl req -new -sha256 -key grpc_client_key_pkcs1.pem -subj "/CN=localhost" -out grpc_client.csr
  openssl x509 -req -in grpc_client.csr -sha384 -CA grpc_ca_cert.pem -CAkey grpc_ca_private.pem \
      -CAcreateserial -out grpc_client_cert.pem
  openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in grpc_client_key_pkcs1.pem -out grpc_client_key.pem

  rm grpc_server.csr grpc_client.csr grpc_client_key_pkcs1.pem grpc_ca_cert.srl

  popd
}

main() {
  generate_grpc_certs
}

main
