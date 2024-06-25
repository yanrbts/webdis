#!/bin/sh

server_name="localhost"
cert_subject="/C=XX/ST=ExampleState/L=ExampleCity/O=ExampleCorp/OU=ExampleDepartment/CN=$server_name"

echo "创建新证书"
rm server.* client.* rootCA.* 2> /dev/null
echo "使用 'pass' 作为每个密码"

# 创建根 CA 证书
echo "生成根 CA 证书..."

openssl genrsa -des3 -passout pass:pass -out rootCA.key 2048
openssl req -passout pass:pass -new -key rootCA.key -out rootCA.csr -subj $cert_subject
cp rootCA.key rootCA.key.orig
openssl rsa -in rootCA.key.orig -out rootCA.key
openssl x509 -req -days 3651 -in rootCA.csr -signkey rootCA.key -out rootCA.crt
cp rootCA.crt rootCA.pem
cat rootCA.key >> rootCA.pem

# 生成服务器证书
echo "生成服务器证书..."

openssl genrsa -des3 -passout pass:pass -out server.key 2048
openssl req -passout pass:pass -new -key server.key -out server.csr -subj $cert_subject
cp server.key server.key.orig
openssl rsa -in server.key.orig -out server.key

echo "authorityKeyIdentifier=keyid,issuer" > server.ext
echo "basicConstraints=critical,CA:FALSE" >> server.ext
echo "keyUsage=digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment" >> server.ext
echo "subjectAltName=DNS:$server_name" >> server.ext

openssl x509 -req -days 3650 -sha256 -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -extfile server.ext -in server.csr -out server.crt

cp server.crt server.pem
cat server.key >> server.pem
cat rootCA.crt >> server.pem

# 生成客户端证书
echo "生成客户端证书..."

openssl genrsa -des3 -passout pass:pass -out client.key 2048
openssl req -passout pass:pass -new -key client.key -out client.csr -subj $cert_subject
cp client.key client.key.orig
openssl rsa -in client.key.orig -out client.key

echo "authorityKeyIdentifier=keyid,issuer" > client.ext
echo "basicConstraints=critical,CA:FALSE" >> client.ext
echo "keyUsage=digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment" >> client.ext
echo "subjectAltName=DNS:$server_name" >> client.ext

openssl x509 -req -days 3650 -sha256 -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -extfile client.ext -in client.csr -out client.crt -passin pass:pass

cp client.crt client.pem
cat client.key >> client.pem

openssl pkcs12 -passout pass:pass -export -inkey client.key -in client.pem -name ClientName -out client.pfx

# 验证证书
echo "验证服务器证书..."
openssl verify -CAfile rootCA.crt server.crt

echo "验证客户端证书..."
openssl verify -CAfile rootCA.crt client.crt

echo "完成"
