import json
import socket  

user_client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

#send = {"method": "getBlockCount"}
#send =  { "method": "getBlockHash", "data": { "block_height": 10}}   
#send = {"method": "getBlockHeader","data": {"block_hash": "00000092c8c033b87a49d72af887f895f5e32d670747a22e79c9e2b495337ffc"}}
send = {"method": "getBlocks","data": {"hash_count" :2,
        "hash_begin" : "0000008239ba7061fd6d594e70afe29b48196dd06f681b312d7695c6b7059ca2",
        "hash_stop" : "000000506371d0796d8908d260f219838a5286d6ed6c346849221ea4e6c44290"
}}


to_send = json.dumps(send)
user_client.connect(("127.0.0.1", 17777))
try:
    user_client.send(to_send.encode('utf-8')) 
    user_received = user_client.recv(2048).decode()
    print("receieve: "+ user_received)
    
    user_client.close()
        
        
    
except ConnectionResetError as e:
    print(e)