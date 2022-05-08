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

police_list={'police1':8001}
print("ticket server switching on")

ds = ('127.0.0.1',8000)
ticket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ticket_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ticket_server.bind(ds)
ticket_server.listen(1)
def dec(val):
    return val
def find_server(message):
    return 'server1'
def receive_on_new_client(conn,addr):
    while True:
        msg = conn.recv(4096)
        with open('./ticket_server_keys/ticketpriv.private', 'rb') as priv2:
            priv_key = priv2.read()
        msg = decrypt(priv_key,msg).decode('utf-8')
        msg=json.loads(msg)
        if 'message' in msg: #and binascii.unhexlify(msg['message'].encode('utf-8'))=='hello':
            ticket1=ticket(msg['id'],datetime.now().timestamp(),10000)
            with open('./police_keys/'+msg['id']+'pub.public', 'rb') as priv2:
                pub_key = priv2.read()
            tic=encrypt(pub_key,ticket1.toJSON().encode('utf-8'))
            print("Ticket 1 sent")
            conn.send(tic)
        
        if 'license' in msg and 'ticket' in msg:
            msg['ticket']=json.loads(dec(msg['ticket']))
            if (msg['ticket']['issue']+msg['ticket']['lifetime'])>datetime.now().timestamp():
                server=find_server(msg['license'])
                ticket2=ticket(msg['ticket']['ID'],datetime.now().timestamp(),10000,server)
                with open('./police_keys/'+msg['ticket']['ID']+'pub.public', 'rb') as priv2:
                    pub_key = priv2.read()
                tic=encrypt(pub_key,ticket2.toJSON().encode('utf-8'))
                print("Ticket 2 sent")
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

# def encrypt(value,key):
#     key = RSA.importKey(key.decode('utf8'))
#     temp=int.from_bytes(value, byteorder='big')
#     cipher = pow(temp,key.d,key.n)
#     byte_len = int(math.ceil(cipher.bit_length() / 8))
#     return cipher.to_bytes(byte_len,byteorder='big')

def serve(conn):
    while True:
        data = conn.recv(1024).decode('utf-8')
        if not data:
            continue
        data=json.loads(data)

        if ('receiver' or 'time') not in data.keys():
            conn.send("0".encode('utf8'))
            

        if data['receiver'] in portlist.keys():
            print(str(data['receiver'])+" public key requested")
            DApriv=''
            clientpub=''
            with open('./Pubkey_DA/PKDApri.private', 'rb') as privatefile:
                DApriv=privatefile.read()
            with open('./Pubkey_clients/'+data['receiver']+'pub.public', 'rb') as publicfile:
                clientpub=publicfile.read()

            data.update({'public_key':clientpub.decode('utf8')})
            conn.send(encrypt(json.dumps(data).encode('utf8'),DApriv))
        
        else:
            conn.send("client not found".encode('utf-8'))

    conn.close()

def Server_init(i):
    try:
        serve(i)
    except:
        print('error with item')

while True:
    connection_from_all_clients()
# print("waiting for client")
# executor = concurrent.futures.ProcessPoolExecutor(len(servers))
# futures = [executor.submit(Server_init, i) for i in servers]
# concurrent.futures.wait(futures)
    # readable,_,_ = select.select(servers, [], [])
    # ready_server = readable[0]
    # print(ready_server)
    # connection, address = ready_server.accept()
    # t1=threading.Thread(target=serve(connection))
