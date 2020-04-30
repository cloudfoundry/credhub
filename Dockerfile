FROM openjdk:8 as build
WORKDIR /app
COPY . /app
RUN ./gradlew bootJar -x test -x check

FROM openjdk:8-jre as run
WORKDIR /app
COPY \
  --from=build \
  /app/applications/credhub-api/build/libs/credhub.jar \
  .

COPY \
  --from=build \
  /app/docker/config/application.yml \
  /app/config/application.yml

COPY \
  --from=build \
  /app/docker/dev_uaa.pem \
  /etc/trusted_cas/dev_uaa.pem

COPY \
 --from=build \
 /app/docker/setup_trust_store.sh \
 .

COPY \
 --from=build \
 /app/docker/start_server.sh \
 .

RUN mkdir -p /etc/config

EXPOSE 9000

ENV TRUST_STORE_PASSWORD=changeme
ENV KEY_STORE_PASSWORD=changeme
ENV ENCRYPTION_PASSWORD=changeme
ENV SERVER_CA_CERT_PATH="/etc/server_certs/server_ca_cert.pem"
ENV SERVER_CA_PRIVATE_KEY_PATH="/etc/server_certs/server_ca_private.pem"
ENV UAA_CA_PATH="/etc/trusted_cas/dev_uaa.pem"
ENV UAA_URL="https://35.196.32.64:8443"
ENV SUBJECT_ALTERNATIVE_NAMES="DNS:localhost, IP:127.0.0.1"

CMD /app/setup_trust_store.sh && /app/start_server.sh
