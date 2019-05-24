import hashlib
import random
import json
import socket  
import threading
import sys
import os
import ecdsa
import time


TRANS_SIZE = 4096

class inf_node():
    
    def __init__ (self, target,  p2p_port, user_port, neighbor_list, beneficiary, file_name, wallet):
        self.file_name = file_name
        
        self.ip = "localhost"
        self.p2p_port = p2p_port
        self.user_port = user_port
        self.neighbor_list = neighbor_list
        
        
        self.version = b"00000002"
        self.target = target
        self.transactions_hash =  b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.beneficiary = bytes(beneficiary, encoding='utf8')
        self.members = [str(self.beneficiary,encoding='utf8')]
        
        self.wallet = wallet
        
        self.p2p_server_ready = False
        self.user_server_ready = False
        
       
        self.pool = []
        self.blocks = [] 
        self.block_hashes = [b"0000000000000000000000000000000000000000000000000000000000000000"]
        self.sucess_txs = []
        self.now_txs = []
        self.prev_block = b"0000000000000000000000000000000000000000000000000000000000000000"
        self.block_height = -1
        self.tx_to_hash = ""
        self.balance = self.getbalance(self.block_height)

        self.threads = []
        self.threads.append(threading.Thread(target = self.p2p_listen))
        self.threads.append(threading.Thread(target = self.user_listen))
        self.threads[0].start()
        self.threads[1].start()
        
        print("waiting for servers ready...")
        while self.p2p_server_ready == False or self.user_server_ready == False:
            pass
        print("finished.")
        
        
        
        
        
        
    def run_and_mine(self):

        while(1):
    
    
            nonce_raw = random.randint(0,99999999)
            nonce_pad = '{0:08d}'.format(nonce_raw)
            nonce_new = bytes(nonce_pad,encoding='utf8') 
            

            
            sucess_tx_sigs = []
            
            for suc_txs in self.sucess_txs:
                for suc_tx in suc_txs:
                    sucess_tx_sigs.append(suc_tx["signature"])
            

            
            for tx in self.pool:
                if tx["sender_pub_key"] not in self.balance:
                    self.balance[tx["sender_pub_key"]] = 0
                if  tx not in self.now_txs and tx["signature"] not in sucess_tx_sigs and self.balance[tx["sender_pub_key"]] >= (tx["value"]+tx["fee"]):
                    if tx["to"] not in self.balance:
                        self.balance[tx["to"]] = 0
                        
                    self.balance[tx["sender_pub_key"]] = self.balance[tx["sender_pub_key"]] - tx["value"] - tx["fee"]
                    self.balance[tx["to"]]+=tx["value"]
                    self.now_txs.append(tx)
                    self.tx_to_hash  += tx["signature"] 

            self.transactions_hash =  bytes(hashlib.sha256(bytes(self.tx_to_hash, encoding='utf8')).hexdigest(),encoding='utf8')
            
            data = self.version + self.prev_block +self.transactions_hash + self.target+ nonce_new + self.beneficiary
           
            sha256_result = hashlib.sha256(data).hexdigest()
            
            
            if sha256_result<=str(self.target,encoding='utf8'):
                print("mined: " + sha256_result)

                                                            
                now_block_height = self.block_height +1 
                now_block = { "prev_block": str(self.prev_block, encoding='utf8'), "version":  2,  "target": str(self.target, encoding='utf8'), "nonce":  int(str(nonce_new, encoding='utf8')),
                             "transactions_hash":  str(self.transactions_hash, encoding='utf8'), "beneficiary": str(self.beneficiary, encoding='utf8'),
                             "transactions": self.now_txs}
                fail_flag = self.sendBlock(now_block)
                
                if fail_flag==True:
                    print('?????')
                else:
                    self.blocks.append(now_block)
                    self.block_hashes.append(bytes(sha256_result,encoding='utf8'))
                    self.tx_to_hash = ""
                    
                    self.sucess_txs.append(self.now_txs)
                    
                    self.block_height = now_block_height
                    self.now_block = now_block
                    self.prev_block = bytes(sha256_result, encoding='utf8')
                    
                    self.now_txs = []
                    self.transactions_hash =  b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    self.balance = self.getbalance(self.block_height)
                    
                    print(self.blocks)
                    print(self.getbalance(self.block_height))
            

        
        
        
    def sendBlock(self, header_data):
        
        
        
        to_send = json.dumps( {"method": "sendBlock", "data": header_data, "height": self.block_height +1 } )
        
        fail_flag = False
        random.shuffle(self.neighbor_list)
        for neighbor in self.neighbor_list:
            p2p_client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            
            
            if p2p_client.connect_ex((neighbor["ip"], neighbor["p2p_port"]))==0:
                print("sendHeader send to: " + str(neighbor["p2p_port"]))
                try:
                    p2p_client.send(to_send.encode('utf-8')) 
                    p2p_received = p2p_client.recv(TRANS_SIZE).decode()
                    print("sendHeader receieve: "+ p2p_received)
                    
                    if json.loads(p2p_received)["error"] == 1:
                        
                        fail_flag = True
                    
                except ConnectionResetError as e:
                    print(e)
            p2p_client.close()
        
        return fail_flag
    
    def int_to_hex(self, int_num, length):
        return (length-len(hex(int_num)[2:]))*'0'+hex(int_num)[2:]
    
    def sha_tx(self,nonce,sender_pub_key,to,value,fee):
        if nonce== None:
            nonce_str = self.int_to_hex(random.randint(0,18446744073709551615),16)
        else:
            nonce_str = self.int_to_hex(nonce,16)
        
        value_str = self.int_to_hex(value,16)
        fee_str =  self.int_to_hex(fee,16)
        
        to_sha = bytes(nonce_str + sender_pub_key + to + value_str + fee_str, encoding='utf8')
        return hashlib.sha256(to_sha).hexdigest()
    

    def check_sig(self, signature, pub_key, message):
        #                 str       str       bytes
        
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pub_key), curve=ecdsa.SECP256k1)
        try:
            result = vk.verify(bytes.fromhex(signature), message)
        except:
            result = False
        
        return result

    
    def check_vaild(self, data, height):
        with open(self.file_name, 'r', encoding='utf8') as config_file:
            config = json.load(config_file)
            
            check_1 = data["version"] == 2
            check_2 = data["target"] == config["target"]
            
            sigs = ""
            for tx in data["transactions"]:
                sigs += tx["signature"]
            
            check_3 = data["transactions_hash"] == hashlib.sha256(bytes(sigs,encoding='utf8')).hexdigest()
           
            block_data = '{0:08d}'.format(data["version"]) + data["prev_block"] +  data["transactions_hash"]  + data["target"] +  data["nonce"] +  data["beneficiary"] 
            block_data = bytes(block_data,encoding='utf8')
            
            

            check_4 =  hashlib.sha256(block_data).hexdigest() <= data["target"]
            
            check_5 = bytes(data["prev_block"], encoding='utf8') in self.block_hashes
            
            balance = self.getbalance(height-1)
            
            sucess_tx_sigs = []
            for block_num in range(height):
                for suc_tx in self.sucess_txs[block_num]:
                    sucess_tx_sigs.append(suc_tx["signature"])
            
            check_6 = True
            

            for tx in data["transactions"]:
                message = bytes(self.sha_tx(tx["nonce"],tx["sender_pub_key"],tx["to"],tx["value"],tx["fee"]),encoding='utf8')
                
                if self.check_sig(tx["signature"], tx["sender_pub_key"], message) and tx["signature"] not in sucess_tx_sigs and balance[tx["sender_pub_key"]] >= (tx["value"]+tx["fee"]):
                    if tx["to"] not in balance:
                        balance[tx["to"]] = 0
                    balance[tx["sender_pub_key"]] -= (tx["value"]+tx["fee"])
                    balance[tx["to"]]+=tx["value"]
                    
                else:
                    check_6 = False
            print(check_1,check_2,check_3,check_4,check_5,check_6, sep=' ')
            
            return check_1 and check_2 and check_3 and check_4 and check_5 and check_6
    
    def p2p_listen(self):
        self.p2p_server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.p2p_server.bind((self.ip, self.p2p_port))
        self.p2p_server.listen(len(self.neighbor_list))
        self.p2p_server_ready = True
        while True:
            conn,addr = self.p2p_server.accept()
                                    
            try:
                
                
                data = conn.recv(TRANS_SIZE).decode()
                
                json_received = json.loads(data)
                print(json_received)
                
                if json_received["method"] == "sendBlock":
                    json_received["data"]["nonce"] = str(json_received["data"]["nonce"])

                    if self.check_vaild(json_received["data"], json_received["height"]):
                        self.now_block = json_received["data"]
                        self.block_height +=1
                        block_data = '{0:08d}'.format(json_received["data"]["version"]) + json_received["data"]["prev_block"] +  json_received["data"]["transactions_hash"] + json_received["data"]["target"] +  json_received["data"]["nonce"] +  json_received["data"]["beneficiary"] 
                        self.prev_block =  bytes(hashlib.sha256(bytes(block_data,encoding='utf8')).hexdigest(),encoding='utf8')
                        self.sucess_txs.append(json_received["data"]["transactions"])
                        self.blocks.append(json_received["data"])
                        self.block_hashes.append(self.prev_block)
                        self.tx_to_hash = ""
                        
                        self.now_txs = []
                        self.transactions_hash =  b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        self.balance = self.getbalance(self.block_height)
                        
                        sendBlocks_reply = json.dumps({"error":0})
                        
                    else:
                        sendBlocks_reply = json.dumps({"error":1})
                        
                    buffer = sendBlocks_reply.encode('utf-8')
                    conn.send(buffer)
                
                if json_received["method"] == "sendTransaction":
                    
                    message = bytes(self.sha_tx(json_received["data"]["nonce"],json_received["data"]["sender_pub_key"],json_received["data"]["to"],json_received["data"]["value"],json_received["data"]["fee"]),encoding='utf8')
                    
                    check = self.check_sig(json_received["data"]["signature"], json_received["data"]["sender_pub_key"], message)
                    

                    if check:
                        sendTransaction_reply = json.dumps({"error":0})
                        self.pool.append( json_received["data"])
                    else:
                        sendTransaction_reply = json.dumps({"error":1})
                        
                    buffer = sendTransaction_reply.encode('utf-8')
                    conn.send(buffer)
                conn.close()
                
                print(self.blocks)
                print(self.getbalance(self.block_height))
                
            except ConnectionResetError as e:
                print(e)
                #to_send = json.dumps({"error":1})
               # conn.send(to_send.encode('utf-8'))
               # conn.close()
                
    def sendTransaction(self,address,amount):
        
       
        nonce = random.randint(0,18446744073709551615)
        sender_pub_key = self.wallet["public_key"]
        to = address
        value = amount
        fee = 0
        
        message = bytes(self.sha_tx(nonce,sender_pub_key,to,value,fee), encoding='utf8')
        private_key = ecdsa.SigningKey.from_string(bytes.fromhex(self.wallet["private_key"]), curve=ecdsa.SECP256k1)
        signature = private_key.sign(message).hex()
        
        data = {"nonce": nonce,
                "sender_pub_key": sender_pub_key,
                "to": to,
                "value": value,
                "fee": fee,
                "signature": signature
                }
        
        to_send = json.dumps( {"method": "sendTransaction", "data": data} )
        
        self.pool.append(data)
        
        fail_flag = False
        random.shuffle(self.neighbor_list)
        for neighbor in self.neighbor_list:
            p2p_client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            
            
            if p2p_client.connect_ex((neighbor["ip"], neighbor["p2p_port"]))==0:
                print("sendTransaction send to: " + str(neighbor["p2p_port"]))
                try:
                    p2p_client.send(to_send.encode('utf-8')) 
                    p2p_received = p2p_client.recv(TRANS_SIZE).decode()
                    print("sendTransaction receieve: "+ p2p_received)
                    
                    if json.loads(p2p_received)["error"] == 1:
                        
                        fail_flag = True
                    
                except ConnectionResetError as e:
                    print(e)
            p2p_client.close()

        return fail_flag
            
    def user_listen(self):   
        self.user_server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.user_server.bind((self.ip, self.user_port))
        self.user_server.listen(len(self.neighbor_list))
        self.user_server_ready = True
        
        while True:
            conn,addr = self.user_server.accept()
            
            try:
                
                
                data = conn.recv(TRANS_SIZE).decode()
                print('recive:',data) 
                json_received = json.loads(data)
                
                if json_received["method"] == "sendtoaddress":

                    to_send = json.dumps({"error":0})
                    conn.send(to_send.encode('utf-8'))
                    self.sendTransaction(json_received["data"]["address"],json_received["data"]["amount"])
                    
                if json_received["method"] == "getbalance":
                    
                    if self.block_height-2 <0:
                        to_send = json.dumps({"error":0, "balance": 0})
                    else:
                        balance = self.getbalance(self.block_height-2)
                        if json_received["data"]["address"] in balance:
                            value = balance[json_received["data"]["address"]]
                        else:
                            value = 0
                        to_send = json.dumps({"error":0, "balance": value})
                    
                    conn.send(to_send.encode('utf-8'))
                    
                    
                    
                    
                conn.close()
            except ConnectionResetError as e:
                print(e)
               # to_send = json.dumps({"error":1})
               # conn.send(to_send.encode('utf-8'))
               # conn.close()
                
                
    def getbalance(self, block_height):
        
        
        for block in self.blocks:
            if block["beneficiary"] not in self.members:
                self.members.append(block["beneficiary"])
        
        for success_txs in self.sucess_txs:
            for success_tx in success_txs:
                if success_tx["sender_pub_key"] not in self.members:
                    self.members.append(success_tx["sender_pub_key"])
                if success_tx["to"] not in self.members:
                    self.members.append(success_tx["to"])

        
        balance = {}
        
        for member in self.members:
            balance[member] = 0
        
        
        
        for block_num in range(block_height+1):
            for tx in self.sucess_txs[block_num]:
                balance[tx["sender_pub_key"]] -= tx["value"]      
                balance[tx["sender_pub_key"]] -= tx["fee"]  
                balance[tx["to"]] += tx["value"] 
                balance[self.blocks[block_num]["beneficiary"]] += tx["fee"] 
            balance[self.blocks[block_num]["beneficiary"]] += 1000
            
        return balance
        
if __name__ == '__main__':
    
    #file_name = sys.argv[1]
    file_name = 'config.json'
    
    with open(file_name, 'r', encoding='utf8') as config_file: 
        config = json.load(config_file)
        
    
        target_in = bytes(config['target'],encoding='utf8')
        neighbor_list = config['neighbor_list']
        p2p_port = config["p2p_port"]
        user_port = config["user_port"]
        beneficiary = config["beneficiary"]
        wallet = config["wallet"]
        
        
        t_node1 = inf_node(target_in, p2p_port, user_port, neighbor_list, beneficiary, file_name, wallet)
        time.sleep(config["delay"])
       
        
        if config["mining"]:
            t_node1.run_and_mine()
        else:
            while 1:
                pass
        

