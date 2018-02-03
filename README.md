# Bargo

Encrypted socks5 and http proxy service

## Useage

Need to set up a service side, and then set up a client. Use the device to connect to the client's service

## Example

According to the computer system and the server system, in the bin directory to download the corresponding version. The following example, the server is linux64 bit, the client is macos

Set up the service side(Your server)

    ./bargo-linux-amd64 -mode server -server-port 50088 -key 123456
    
Set up the client(Your computer)

    ./bargo-mac-amd64 -mode client -server-host xxx.xxx.xxx.xxx -server-port 50088 -key 123456
    
The default will listen to 1080 port as socks5 proxy port, 1081 port as http proxy port. If you want to modify it can be viewed

    ./bargo-mac-amd64 -h

## Use Docker

```
0x1: build

git clone https://github.com/sinchie/bargo.git
cd bargo
sudo docker build -t bargo:latest .

0x2: run

sudo docker run -d --name bargo_server -p 50080:50080 -e bargo_mode=server -e bargo_server_port=50080 -bargo_key=1q2w3e4r bargo:latest
```
## End

Well, your computer, browser, mobile phone or other devices can connect to your client proxy service, using socks5 protocol or http protocol
