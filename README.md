# miniVPN-seed_ubuntu
Practice of net secuiruty. I run it on seed_ubuntu 16.04.

It contains miniVPN_client and miniVPN_server,which supports multiclients.  
You can use dockers or just different virtual machines to run the clients and server.

The programme supports:  
1.Host-to host Tunnel bases on TCP connection(port 4433).  
2.Using TLS protocol for session encryption.  
3.Dual Authentication between server and client.  
4.Multiclients connections.  
  
Follow the procedure supplied below to configure your environment.  
1.Create a docker as Internet(external net),name it extranet:  
$ sudo docker network create --subnet=10.0.2.0/24 --gateway=10.0.2.8 --opt "com.docker.network.bridge.name"="docker1" extranet  
2.Create a docker as internal net,name it intranet:
$ sudo docker network create --subnet=192.168.60.0/24 --gateway=192.168.60.1 --opt "com.docker.network.bridge.name"="docker2" intranet  
3.Create a docker as a external client,name it HostU,deploy it on extranet:  
$ sudo docker run -it --name=HostU --hostname=HostU --net=extranet --ip=10.0.2.7 --privileged "seedubuntu" /bin/bash  
4.Create a docker as a internal server,name it HostV,deploy it on intranet:  
$sudo docker run -it --name=HostV --hostname=HostV --net=intranet --ip=192.168.60.101 --privileged "seedubuntu" /bin/bash  
