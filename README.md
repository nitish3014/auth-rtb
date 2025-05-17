## Auth Service
  
## Environment Variables
```shell
CYPHER_KEY = 32_BYTE_KEY;  # eg: LEwZ3k4Z8WeiTxJmyp0qOKZL+DoXJg2hXawYfKGZjZsXarbfknCtarb5JHFphnUm
DATABASE_HOST = localhost; # use your local db credentials
DATABASE_NAME = bb_auth;
DATABASE_PASSWORD = password;
DATABASE_PORT = 5432;
DATABASE_SCHEMA = bellboy;
DATABASE_USERNAME = bb_auth_rw;
ENVIRONMENT = dev
```

## Steps to create private and public keys for signing jwt
openssl is installed by default in all mac os versions and linux distributions.
```shell
# Create RSA key pair
openssl genrsa -out key.pem 2048

# Extract public key from key.pem
openssl  rsa -in key.pem -pubout -out public.pem

# Private key needs to be in PEM-encoded PKCS#8 format
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in key.pem -out private.pem

# Delete key.pem file and place the private and public key files in resources/certs folder.
```
