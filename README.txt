# MySNS-2-FASE

Necessário Java 21 ou superior

Correr server:
A localização da pasta deve ser : ~/Projeto 2 Segurança/MySNS-2-FASE/src/main/java

java 
-Djavax.net.ssl.keyStore=keystore.server 

-Djavax.net.ssl.keyStorePassword=server com/securehub/securemedfileshub/MySNSServer  12345

Correr cliente: 
A localização da pasta deve ser: ~/Projeto 2 Segurança/MySNS-2-FASE/src/main/java/com/securehub/securemedfileshub

Criar user:

java 
-Djavax.net.ssl.trustStore=truststore.client 

-Djavax.net.ssl.trustStorePassword=server MySNS.java -a 127.0.0.1:12345  -au miguel miguel miguel.cer

java -Djavax.net.ssl.trustStore=truststore.client -Djavax.net.ssl.trustStorePassword=server MySNS.java -a 127.0.0.1:12345  -m miguel -p miguel -u henrique -sc Parte2Enunciado.pdf

java -Djavax.net.ssl.trustStore=truststore.client -Djavax.net.ssl.trustStorePassword=server MySNS.java -a 127.0.0.1:12345  -m miguel -p miguel -u henrique -sa Parte2Enunciado.pdf

java -Djavax.net.ssl.trustStore=truststore.client -Djavax.net.ssl.trustStorePassword=server MySNS.java -a 127.0.0.1:12345  -m miguel -p miguel -u henrique -se Parte1Enunciado.pdf

java -Djavax.net.ssl.trustStore=truststore.client -Djavax.net.ssl.trustStorePassword=server MySNS.java -a 127.0.0.1:12345 -u henrique -p henrique -g Parte1Enunciado.pdf
