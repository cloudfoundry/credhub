# Running CredHub with Docker

To run CredHub with Docker use the command:

```
docker run -p 9000:9000 \
    -e TRUST_STORE_PASSWORD=<some-password> \
    -e KEY_STORE_PASSWORD=<some-password> \
    -e ENCRYPTION_PASSWORD=<some-password> \
    -v /tmp/certs:/etc/server_certs \
    pcfseceng/credhub:latest`
```

To run with UAA:

```
docker run -p 9000:9000 \
    -e TRUST_STORE_PASSWORD=<some-password> \
    -e KEY_STORE_PASSWORD=<some-password> \
    -e ENCRYPTION_PASSWORD=<some-password> \
    -v /tmp/certs:/etc/server_certs \
    [ -e UAA_URL=<uaa-url> \
    -e UAA_CA_PATH=<some-path> \
    -v <local-uaa-ca-dir>:<some-path-dir> \ ]
    pcfseceng/credhub:latest`
```

This command specifies CredHub to run on port 9000 and mounts the certs to your local machine. 
**You will need these certs later to log on to CredHub!**


In order to login to your newly running CredHub you need to specify some ca_certs. These certs are used to establish trust between the client (CLI), CredHub, and UAA. 
The CredHub CA cert was mounted onto your host machine via the volume mount in the previous command.
For UAA, you can target CredHub's hosted **DEVELOPMENT** UAA.

`credhub login -s https://localhost:9000 -u credhub -p password --ca-cert /tmp/certs/server_ca_cert.pem --ca-cert /tmp/certs/dev_uaa.pem`

However, we recommend you bring yor own UAA!  To specify your own UAA pem just change out the path.

`credhub login -s https://localhost:9000 -u credhub -p password --ca-cert /tmp/certs/server_ca_cert.pem --ca-cert /PATH/TO/YOUR/uaa.pem`
