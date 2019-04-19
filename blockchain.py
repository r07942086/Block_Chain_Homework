import hashlib
import random
import json
import socket  
import threading
import sys
import os

TRANS_SIZE = 4096

class inf_node():
    
    def __init__ (self, target,  p2p_port, user_port, neighbor_list):
        self.ip = "localhost"
        self.p2p_port = p2p_port
        self.user_port = user_port
        self.neighbor_list = neighbor_list
        
        self.version = b"00000001"
        self.target = target
        self.merkle_root =  b"0000000000000000000000000000000000000000000000000000000000000000"
        
        self.p2p_server_ready = False
        self.user_server_ready = False
        
        if os.path.isfile('node_blocks' + str(p2p_port) + '.txt'):
            with open('node_blocks' + str(p2p_port) + '.txt', 'r') as read_file:
                lines = read_file.readlines()
                if len(lines)>0:
                    last_block = json.loads(lines[-1])
                    self.prev_block = bytes(last_block["block_hash"], encoding='utf8')
                    self.nonce =  b"00000000"
                    self.block_height = len(lines)-1
                    print("height : " +  str(self.block_height))
                    if self.sendHeader(last_block):
                        self.getBlocks(0, "0000000000000000000000000000000000000000000000000000000000000000", '0')
                else:
                    self.prev_block = b"0000000000000000000000000000000000000000000000000000000000000000"
                    self.nonce =  b"00000000"
                    self.block_height = -1
                
        else:

            
            self.prev_block = b"0000000000000000000000000000000000000000000000000000000000000000"
            self.nonce =  b"00000000"
            self.block_height = -1
            with open('node_blocks' + str(p2p_port) + '.txt', 'w') as outfile:
                pass
            self.getBlocks(0, "0000000000000000000000000000000000000000000000000000000000000000", '0')


        self.threads = []
        self.threads.append(threading.Thread(target = self.p2p_listen))
        self.threads.append(threading.Thread(target = self.user_listen))
        self.threads[0].start()
        self.threads[1].start()
        
        while self.p2p_server_ready == False or self.user_server_ready == False:
            pass
        
        
        
        
        
        
        
    def run_and_mine(self):

        while(1):
    
    
            nonce_raw = random.randint(0,99999999)
            nonce_pad = '{0:08d}'.format(nonce_raw)
            nonce_new = bytes(nonce_pad,encoding='utf8') 
            
            data = self.version + self.prev_block + self.merkle_root + self.target+ nonce_new
           
            sha256_result = hashlib.sha256(data).hexdigest()
            
            
            if sha256_result<=str(self.target,encoding='utf8'):
                print("mined: " + sha256_result)
                
                now_block_height = self.block_height +1 
                now_block = { "block_hash": sha256_result, "block_header":  str(data, encoding='utf8') , "block_height": now_block_height}
                fail_flag = self.sendHeader(now_block)
                
                if fail_flag==True:
                    self.getBlocks(0, "0000000000000000000000000000000000000000000000000000000000000000", '0')
                else:
                    if now_block != self.block_height:
                        self.block_height = now_block_height
                        self.now_block = now_block
                        with open('node_blocks' + str(self.p2p_port) + '.txt', 'a+', encoding='utf8') as outfile: 
                            json.dump(self.now_block, outfile)
                            outfile.write("\n")
                        self.prev_block = bytes(sha256_result, encoding='utf8') 
                
                
            
            
            
            
    def sendHeader(self, header_data):
        
        
        
        to_send = json.dumps( {"method": "sendHeader", "data": header_data} )
        
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

        

        
    def getBlocks(self, hash_count, hash_begin, hash_stop):
        
        
        
        
        if len(self.neighbor_list)>0:
            random.shuffle(self.neighbor_list)
            for neighbor in self.neighbor_list:
                p2p_client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                
                if p2p_client.connect_ex((neighbor["ip"], neighbor["p2p_port"]))==0:
                    print("getblocks send to: " + str(neighbor["p2p_port"]))
            
                    try:
                        
                        
                        to_send = json.dumps( {"method": "getBlocks", "data": {"hash_count" : hash_count, "hash_begin" :  hash_begin, "hash_stop" : hash_stop}})
                        p2p_client.send(to_send.encode('utf-8'))
                        
                        recv_data = ""
                        
                        
                        while 1:
                            
                            recv_buffer = p2p_client.recv(TRANS_SIZE).decode()
                            recv_data += recv_buffer
                            
                            if not recv_buffer:
                                break
                            
                        json_recv = json.loads(recv_data)
                        
                        if json_recv["error"]==0:
                            
                            if hash_count ==0:
                                if hash_begin == "0000000000000000000000000000000000000000000000000000000000000000":
                                    with open('node_blocks' + str(self.p2p_port) + '.txt', 'w', encoding='utf8') as outfile:
                                        self.block_height = -1
                                        for block in json_recv["result"]:
                                            self.block_height += 1
                                            self.now_block = { "block_hash": hashlib.sha256(bytes(block, encoding='utf8')).hexdigest(), "block_header":  block, "block_height": self.block_height}
                                            self.prev_block = bytes(hashlib.sha256(bytes(block, encoding='utf8')).hexdigest(), encoding='utf8')
                                            json.dump(self.now_block, outfile)
                                            outfile.write("\n")
                                            
                                        p2p_client.close()
                                        break
                                else:
                                    
                                    with open('node_blocks' + str(self.p2p_port) + '.txt', 'a+', encoding='utf8') as outfile:
                                        
                                        for block in json_recv["result"]:
                                            self.block_height += 1
                                            self.now_block = { "block_hash": hashlib.sha256(bytes(block, encoding='utf8')).hexdigest(), "block_header":  block, "block_height": self.block_height}
                                            self.prev_block = bytes(hashlib.sha256(bytes(block, encoding='utf8')).hexdigest(), encoding='utf8')
                                            json.dump(self.now_block, outfile)
                                            outfile.write("\n")
                                            
                                        p2p_client.close()
                                        break
                            else:
                                
                                
                                with open('node_blocks' + str(self.p2p_port) + '.txt', 'w', encoding='utf8') as outfile:
                                    self.block_height = -1
                                    for block in json_recv["result"]:
                                        self.block_height += 1
                                        self.now_block = { "block_hash": hashlib.sha256(bytes(block, encoding='utf8')).hexdigest(), "block_header":  block, "block_height": self.block_height}
                                        self.prev_block = bytes(hashlib.sha256(bytes(block, encoding='utf8')).hexdigest(), encoding='utf8')
                                        json.dump(self.now_block, outfile)
                                        outfile.write("\n")
                                        
                                    p2p_client.close()
                                    break
                        else:
                            pass
                            print("getBlocks got error")
                            
                            
                             
                    except ConnectionResetError as e:
                        print(e)
                    
                p2p_client.close()
                    
    
    def getBlockCount(self):
        return {"error": 0,  "result":self.block_height+1}
    
    def getBlockHash(self, block_height):
        
        if block_height>self.block_height:
            
            return {"error": 1,  "result": None}   
        else:
            with open('node_blocks' + str(self.p2p_port) + '.txt', 'r', encoding='utf8') as readfile:
                lines = readfile.readlines()
                BlockHash = json.loads(lines[block_height])["block_hash"]
                return {"error": 0,  "result": BlockHash}
        
    def getBlockHeader(self, block_hash):
        with open('node_blocks' + str(self.p2p_port) + '.txt', 'r', encoding='utf8') as readfile:
            lines = readfile.readlines()
            for line in lines:
                json_line = json.loads(line)
                if block_hash == json_line["block_hash"]:
                    
                    prev_block = json_line["block_header"][8:72]
                    merkle_root = "0000000000000000000000000000000000000000000000000000000000000000"
                    target = json_line["block_header"][136:200]
                    nonce = json_line["block_header"][200:]
                    
                    result = {"version" : 1, "prev_block" : prev_block, "merkle_root": merkle_root, "target": target, "nonce": nonce}
                    
                    
                    return {"error": 0,  "result": result}
                
            return {"error": 1,  "result": None}
    
    def p2p_listen(self):
        self.p2p_server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.p2p_server.bind((self.ip, self.p2p_port))
        self.p2p_server.listen(len(self.neighbor_list))
        self.p2p_server_ready = True
        while True:
            conn,addr = self.p2p_server.accept()
                                    
            try:
                get_block_flag = False
                
                data = conn.recv(TRANS_SIZE).decode()
                print('recive:',data) 
                json_received = json.loads(data)
                
                if json_received["method"] == "sendHeader":
                    
                    if json_received["data"]["block_height"] < self.block_height:
                        to_send =  json.dumps({"error":1})
                        conn.send(to_send.encode('utf-8'))
                    else:
                        
                        sha256_vertify = hashlib.sha256(bytes(json_received["data"]["block_header"],encoding='utf8')).hexdigest()
                        if json_received["data"]["block_hash"] <= str(self.target,encoding='utf8') and json_received["data"]["block_hash"] == sha256_vertify:
                            if json_received["data"]["block_height"]==self.block_height+1 and str(self.prev_block, encoding='utf8') == json_received["data"]["block_header"][8:72]:
                                self.now_block = json_received["data"]
                                self.block_height +=1
                                self.prev_block =  bytes(json_received["data"]["block_hash"],encoding='utf8')
                                
                                with open('node_blocks' + str(self.p2p_port) + '.txt', 'a+', encoding='utf8') as outfile: 
                                    json.dump(self.now_block, outfile)
                                    outfile.write("\n")
                                    
                                to_send =  json.dumps({"error":0})
                                conn.send(to_send.encode('utf-8')) 
                            elif json_received["data"]["block_height"]==self.block_height:
                                to_send =  json.dumps({"error":0})
                                conn.send(to_send.encode('utf-8')) 
                            else:
                                to_send =  json.dumps({"error":0})
                                conn.send(to_send.encode('utf-8'))
                                get_block_flag = True #再來處理這ˇ
                        else:
                            to_send =  json.dumps({"error":1})
                            conn.send(to_send.encode('utf-8'))
                                
                elif json_received["method"] == "getBlocks":
                    blocks = []
                    out_flag = False
                    
                    
                    
                    with open('node_blocks' + str(self.p2p_port) + '.txt', 'r', encoding='utf8') as readfile:
                        
                        lines = readfile.readlines()
                        
                        if json_received["data"]["hash_count"] != 0 and len(lines)>= json_received["data"]["hash_count"] and json_received["data"]["hash_begin"]=="0" and json_received["data"]["hash_stop"]=="0" :
                            for line in lines[:json_received["data"]["hash_count"]+1]:
                                blocks.append(json.loads(line)["block_header"])
                            if len(blocks)>0:          
                                getBlocks_reply = json.dumps({"error":0, "result": blocks})
                            else:
                                getBlocks_reply = json.dumps({"error":1, "result": []})
                            
                        elif json_received["data"]["hash_count"] == 0 and len(lines)>= json_received["data"]["hash_count"] and json_received["data"]["hash_begin"]=="0000000000000000000000000000000000000000000000000000000000000000" and json_received["data"]["hash_stop"]=="0" :
                            if json_received["data"]["hash_begin"] == "0000000000000000000000000000000000000000000000000000000000000000":
                                    out_flag = True
                            for line in lines:
                                
                                
                                
                                if out_flag==True:
                                    blocks.append(json.loads(line)["block_header"])
                                    
    
                                if json.loads(line)["block_hash"]==json_received["data"]["hash_begin"]:
                                    out_flag = True
                                elif json.loads(line)["block_hash"]==json_received["data"]["hash_stop"]:
                                    out_flag = False
                            if len(blocks)>0:          
                                getBlocks_reply = json.dumps({"error":0, "result": blocks})
                            else:
                                getBlocks_reply = json.dumps({"error":1, "result": []})
                            


                        else:
                            for line in lines:
                                if out_flag==True:
                                    blocks.append(json.loads(line)["block_header"])
                                    
    
                                if json.loads(line)["block_hash"]==json_received["data"]["hash_begin"]:
                                    out_flag = True
                                elif json.loads(line)["block_hash"]==json_received["data"]["hash_stop"]:
                                    out_flag = False
                            
                            
                            if len(blocks)>0 and len(blocks)==json_received["data"]["hash_count"]:          
                                getBlocks_reply = json.dumps({"error":0, "result": blocks})
                            else:
                                getBlocks_reply = json.dumps({"error":1, "result": []})
                            
                        buffer = getBlocks_reply.encode('utf-8')
                        conn.send(buffer)
                        
                   
                conn.close()
                
                if get_block_flag:
                    print("listen and get")
                    self.getBlocks(json_received["data"]["block_height"], "0","0")
                
            except ConnectionResetError as e:
                print(e)
                

            
    def user_listen(self):   
        self.user_server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.user_server.bind((self.ip, self.user_port))
        self.user_server.listen(len(self.neighbor_list))
        self.user_server_ready = True
        
        while True:
            conn,addr = self.user_server.accept()
            
            print(conn,addr)
            print(conn.getpeername())
            
            
            try:
                
                
                data = conn.recv(TRANS_SIZE).decode()
                print('recive:',data) 
                json_received = json.loads(data)
                
                if json_received["method"] == "getBlockCount":
                    to_send = json.dumps(self.getBlockCount())
                    conn.send(to_send.encode('utf-8'))
                elif json_received["method"] == "getBlockHash":
                    to_send = json.dumps(self.getBlockHash(json_received["data"]["block_height"]))
                    conn.send(to_send.encode('utf-8'))
                elif json_received["method"] == "getBlockHeader":
                    to_send = json.dumps(self.getBlockHeader(json_received["data"]["block_hash"]))
                    conn.send(to_send.encode('utf-8'))
                
                conn.close()
                
            except ConnectionResetError as e:
                print(e)
        
if __name__ == '__main__':
    
    file_name = sys.argv[1]
    with open(file_name) as config_file:  
        config = json.load(config_file)
        
    
        target_in = bytes(config['target'],encoding='utf8')
        neighbor_list = config['neighbor_list']
        p2p_port = config["p2p_port"]
        user_port = config["user_port"]
        

        
        t_node1 = inf_node(target_in, p2p_port, user_port, neighbor_list)
        
        
        t_node1.run_and_mine()
        

