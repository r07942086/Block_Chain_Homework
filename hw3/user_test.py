import json
import socket  

user_client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

#send = {"method": "getBlockCount"}
#send =  { "method": "getBlockHash", "data": { "block_height": 10}}   
#send = {"method": "getBlockHeader","data": {"block_hash": "00000092c8c033b87a49d72af887f895f5e32d670747a22e79c9e2b495337ffc"}}
'''
send = {
  "method": "sendBlock",
  "height": 0,
  "data": {
    "version": 2,
    "prev_block": "0000062d20c91f41d74aa760f92810915020a518a7f148cb6f832e5c7ca2c59c",
    "transactions_hash": "058f3d0d49fe1e2a0ca02d778dc21641005ed6655d47a151e6b790caaa94cc9e",
    "beneficiary": "4643bb6b393ac20a6175c713175734a72517c63d6f73a3ca90a15356f2e967da03d16431441c61ac69aeabb7937d333829d9da50431ff6af38536aa262497b27",
    "target": "0000100000000000000000000000000000000000000000000000000000000000",
    "nonce": 7240002,
    "transactions": [
      {
        "fee": 3,
        "nonce": 0,
        "sender_pub_key": "4643bb6b393ac20a6175c713175734a72517c63d6f73a3ca90a15356f2e967da03d16431441c61ac69aeabb7937d333829d9da50431ff6af38536aa262497b27",
        "signature": "868929bdd06a1dca18d9b41cffbacd09b36a22d06ab53bad16ede9094a4fc73412e37402366db89c5b6c2358f71aabfd279862455ec8fb278a9ca95e8f6563b6",
        "to": "4643bb6b393ac20a6175c713175734a72517c63d6f73a3ca90a15356f2e967da03d16431441c61ac69aeabb7937d333829d9da50431ff6af38536aa262497b28",
        "value": 10
      },
      {
        "fee": 3,
        "nonce": 1,
        "sender_pub_key": "4643bb6b393ac20a6175c713175734a72517c63d6f73a3ca90a15356f2e967da03d16431441c61ac69aeabb7937d333829d9da50431ff6af38536aa262497b27",
        "signature": "6b4a01ce0bbc7f81a240f45b3e726091ce94270c9e1e26c70196b56f2d0e6d87763a4852b5cf1c19b1a0a3f42416bf88bcb2e1973e24706616006f7a0bcc6948",
        "to": "4643bb6b393ac20a6175c713175734a72517c63d6f73a3ca90a15356f2e967da03d16431441c61ac69aeabb7937d333829d9da50431ff6af38536aa262497b28",
        "value": 10
      }
    ]
  }
}
'''
send = { "method": "sendtoaddress",
            "data": {
                "address": "4643bb6b393ac20a6175c713175734a72517c63d6f73a3ca90a15356f2e967da03d16431441c61ac69aeabb7937d333829d9da50431ff6af38536aa262497b17",
                "amount": 600
            }
        }

'''
send = {
        "method": "getbalance",
        "data": {
            "address": "4643bb6b393ac20a6175c713175734a72517c63d6f73a3ca90a15356f2e967da03d16431441c61ac69aeabb7937d333829d9da50431ff6af38536aa262497b17"
        }
    }
'''
to_send = json.dumps(send)
user_client.connect(("127.0.0.1", 10001))
try:
    user_client.send(to_send.encode('utf-8')) 
    user_received = user_client.recv(2048).decode()
    print("receieve: "+ user_received)
    
    user_client.close()
        
        
    
except ConnectionResetError as e:
    print(e)