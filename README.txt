# MySNS-2-FASE

Correr server:
java 
-Djavax.net.debug=ssl,handshake  
-Djavax.net.ssl.keyStore=keystore.server 
-Djavax.net.ssl.keyStorePassword=server com/securehub/securemedfileshub/MySNSServer  12345

Criar user:
java 
-Djavax.net.ssl.trustStore=truststore.client 
-Djavax.net.ssl.trustStorePassword=server MySNS.java -a 127.0.0.1:12345  -au miguel miguel miguel.cer
