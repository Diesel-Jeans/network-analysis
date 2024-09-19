# Creating domain.crt and domain.key
1. openssl req -newkey rsa:2048 -keyout domain.key -out domain.csr -nodes
2. openssl req -x509 -sha256 -days 9999 -newkey rsa:2048 -keyout rootCA.key -out rootCA.crt -nodes
3. Create domain.txt
4. openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in domain.csr -out domain.crt -days 9999 -CAcreateserial -extfile domain.txt
5. openssl x509 -text -noout -in domain.crt