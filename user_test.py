import json
import socket  

user_client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

#send = {"method": "getBlockCount"}
#send =  { "method": "getBlockHash", "data": { "block_height": 10}}   
send = {"method": "getBlockHeader","data": {"block_hash": "00000092c8c033b87a49d72af887f895f5e32d670747a22e79c9e2b495337ffc"}}


to_send = json.dumps(send)
user_client.connect(("127.0.0.1", 23456))
try:
    user_client.send(to_send.encode('utf-8')) 
    user_received = user_client.recv(2048).decode()
    print("receieve: "+ user_received)
    
    user_client.close()
        
        
    
except ConnectionResetError as e:
    print(e)