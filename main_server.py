import socket
import json
import select
import threading
import binascii
import math
from Crypto.PublicKey import RSA
import concurrent.futures
from classes import ticket,decrypt,encrypt
from datetime import datetime
def dec(val):
    return val
police_list={'police1':8001}
main_server_list={'server1':8080,'server2':8081}
print("Enter your name")
name=input()
ds = ('127.0.0.1',main_server_list[name])
ticket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ticket_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ticket_server.bind(ds)
ticket_server.listen(1)
db={'server1':{'12345':{'name':'bharath','address':'xyz'}}}
def receive_on_new_client(conn,addr):
    while True:
        msg = conn.recv(4096)
        with open('./main_server_keys/main_'+name+'.private','rb') as priv2:
            priv_key = priv2.read()
        msg = decrypt(priv_key,msg).decode('utf-8')
        msg=json.loads(msg)

        if 'license' in msg and 'ticket' in msg:
            msg['ticket']=json.loads(dec(msg['ticket']))
            if (msg['ticket']['issue']+msg['ticket']['lifetime'])>datetime.now().timestamp():
                details=db[name][str(msg['license'])]
                with open('./police_keys/'+msg['ticket']['ID']+'pub.public', 'rb') as priv2:
                    pub_key = priv2.read()
                tic=encrypt(pub_key,json.dumps(details).encode('utf-8'))
                print("Details sent")
                conn.send(tic)
            else:
                conn.send(b'expired')

def connection_from_all_clients():
    t=len(police_list.keys())
    count=0
    while True:
        print("Waiting for connections")
        c1, addr = ticket_server.accept()
        print("New connection connected")   
        t1=threading.Thread(target=receive_on_new_client,args=(c1,addr))
        t1.start()
        count+=1
        print(count)
        if count==t:
            print("All connections connected")
            break

while True:
    connection_from_all_clients()