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
        
        if os.path.isfile('node_blocks' + str(p2p_port) + '.txt'):
            with open('node_blocks' + str(p2p_port) + '.txt', 'r') as read_file:
                lines = read_file.readlines()
                self.prev_block = bytes(json.loads(lines[-1])["block_hash"], encoding='utf8')
                self.nonce =  b"00000000"
                self.block_height = len(lines)
                
        else:

            
            self.prev_block = b"0000000000000000000000000000000000000000000000000000000000000000"
            self.nonce =  b"00000000"
            self.block_height = 0
            with open('node_blocks' + str(p2p_port) + '.txt', 'w') as outfile:
                pass

        self.threads = []
        self.threads.append(threading.Thread(target = self.p2p_listen))
        self.threads[0].start()

        
        while self.p2p_server_ready == False:
            pass
        
        
        self.getBlocks(0, str(self.prev_block, encoding='utf8'), '0')
# =============================================================================
#         p2p_client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# 
#         if len(self.neighbor_list)>0:
#             
#             for neighbor in self.neighbor_list:
#                 
#                 if p2p_client.connect_ex((neighbor["ip"], neighbor["p2p_port"]))==0:
#                     
#             
#                     try:
#                         to_send = json.dumps( {"method": "getBlocks", "data": {"hash_count" : 0, "hash_begin" :  str(self.prev_block, encoding='utf8'), "hash_stop" : '0'}})
#                         p2p_client.send(to_send.encode('utf-8'))
#                         recv_data = p2p_client.recv(TRANS_SIZE).decode()
#                         print(recv_data)
#                         json_recv = json.loads(recv_data)
#                         if json_recv["error"]==0:
#                             with open('node_blocks' + str(self.p2p_port) + '.txt', 'a+', encoding='utf8') as outfile:
#                                 
#                                 for block in json_recv["result"]:
#                                     self.block_height += 1
#                                     self.now_block = { "block_hash": hashlib.sha256(bytes(block, encoding='utf8')).hexdigest(), "block_header":  block, "block_height": self.block_height}
#                                     self.prev_block = bytes(hashlib.sha256(bytes(block, encoding='utf8')).hexdigest(), encoding='utf8')
#                                     json.dump(self.now_block, outfile)
#                                     outfile.write("\n")
#                                 
#                     except ConnectionResetError as e:
#                         print(e)
#                     
#                     p2p_client.close()
# =============================================================================
        
        
        
        
    def run_and_mine(self):

        

        
        
        while(1):
    
    
            nonce_raw = random.randint(0,99999999)
            nonce_pad = '{0:08d}'.format(nonce_raw)
            nonce_new = bytes(nonce_pad,encoding='utf8') 
            
            data = self.version + self.prev_block + self.merkle_root + self.target+ nonce_new
           
            sha256_result = hashlib.sha256(data).hexdigest()
            
            
            if sha256_result<=str(self.target,encoding='utf8'):
                print(sha256_result)
                self.block_height +=1
                self.now_block = { "block_hash": sha256_result, "block_header":  str(data, encoding='utf8') , "block_height": self.block_height}
                with open('node_blocks' + str(self.p2p_port) + '.txt', 'a+', encoding='utf8') as outfile: 
                    json.dump(self.now_block, outfile)
                    outfile.write("\n")
                
                self.sendHeader(self.now_block)

                self.prev_block = bytes(sha256_result, encoding='utf8') 
                
                
            
            
            
            
    def sendHeader(self, header_data):
        
        p2p_client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        
        to_send = json.dumps( {"method": "sendHeader", "data": header_data} )
        
        fail_flag = False
        for neighbor in self.neighbor_list:
            if p2p_client.connect_ex((neighbor["ip"], neighbor["p2p_port"]))==0:
                try:
                    p2p_client.send(to_send.encode('utf-8')) 
                    p2p_received = p2p_client.recv(TRANS_SIZE).decode()
                    print("sendHeader receieve: "+ p2p_received)
                    
                    if json.loads(p2p_received)["error"] == 1:
                        
                        fail_flag = True
                    
                except ConnectionResetError as e:
                    print(e)
                p2p_client.close()
        
        if fail_flag==True:
            self.getBlocks(0, str(self.prev_block, encoding='utf8'), "0")
        
        #to_send = json.dumps( {"method": "getBlocks", "data": {"hash_count" : json_received["data"]["block_height"] - self.block_height, "hash_begin" : str(self.prev_block, encoding = 'uft8'), "hash_stop" : json_received["data"]["block_hash"]}})
        #conn.send(to_send.encode('utf-8'))
        
    def getBlocks(self, hash_count, hash_begin, hash_stop):
        
        
        p2p_client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        
        if len(self.neighbor_list)>0:
            
            for neighbor in self.neighbor_list:
                
                if p2p_client.connect_ex((neighbor["ip"], neighbor["p2p_port"]))==0:
                    
            
                    try:
                        to_send = json.dumps( {"method": "getBlocks", "data": {"hash_count" : hash_count, "hash_begin" :  hash_begin, "hash_stop" : hash_stop}})
                        p2p_client.send(to_send.encode('utf-8'))
                        recv_data = p2p_client.recv(TRANS_SIZE).decode()
                        json_recv = json.loads(recv_data)
                        if json_recv["error"]==0:
                            with open('node_blocks' + str(self.p2p_port) + '.txt', 'a+', encoding='utf8') as outfile:
                                
                                for block in json_recv["result"]:
                                    self.block_height += 1
                                    self.now_block = { "block_hash": hashlib.sha256(bytes(block, encoding='utf8')).hexdigest(), "block_header":  block, "block_height": self.block_height}
                                    self.prev_block = bytes(hashlib.sha256(bytes(block, encoding='utf8')).hexdigest(), encoding='utf8')
                                    json.dump(self.now_block, outfile)
                                    outfile.write("\n")
                        else:
                            
                            with open('node_blocks' + str(self.p2p_port) + '.txt', 'r', encoding='utf8') as readfile:
                                lines = readfile.readlines
                            with open('node_blocks' + str(self.p2p_port) + '.txt', 'w', encoding='utf8') as writefile:
                                 for i in range(len(lines)-1):
                                     writefile.write(lines[i])
                                     writefile.write("\n")
                             
                    except ConnectionResetError as e:
                        print(e)
                    
                    p2p_client.close()
                    
    
    def getBlockCount(self):
        return {"error": 0,  "result":self.block_height}
    
    def p2p_listen(self):
        self.p2p_server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.p2p_server.bind((self.ip, self.p2p_port))
        self.p2p_server.listen(len(self.neighbor_list))
        self.p2p_server_ready = True
        while True:
            conn,addr = self.p2p_server.accept()
            
            print(conn,addr)
            print(conn.getpeername())
            
# =============================================================================
#             check_flag = False
#             for nei in self.neighbor_list:
#                 if conn.getsockname()[0]==nei["ip"] and conn.getsockname()[1] == nei["p2p_port"]:
#                     check_flag = True
#                     break
#             if check_flag==False:
#                 self.neighbor_list.append({"ip":conn.getsockname()[0], "p2p_port":conn.getsockname()[1]})
#             
#             
# =============================================================================
            
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
                        if json_received["data"]["block_hash"] <= str(self.target,encoding='utf8') and json_received["data"]["block_hash"] == sha256_vertify and str(self.prev_block, encoding='utf8') == json_received["data"]["block_header"][8:72]:
                            if json_received["data"]["block_height"]==self.block_height+1:
                                self.now_block = json_received["data"]
                                self.block_height +=1
                                self.prev_block =  bytes(json_received["data"]["block_hash"],encoding='utf8')
                                
                                with open('node_blocks' + str(self.p2p_port) + '.txt', 'a+', encoding='utf8') as outfile: 
                                    json.dump(self.now_block, outfile)
                                    outfile.write("\n")
                                    
                                to_send =  json.dumps({"error":0})
                                conn.send(to_send.encode('utf-8')) 
                                
                            else:
                                to_send =  json.dumps({"error":0})
                                conn.send(to_send.encode('utf-8'))
                                get_block_flag = True
                                get_block_hash_count = json_received["data"]["block_height"] - self.block_height
                                get_block_hash_begin = str(self.prev_block, encoding = 'uft8')
                                get_block_hash_stop =  json_received["data"]["block_hash"]
                                
                elif json_received["method"] == "getBlocks":
                    blocks = []
                    out_flag = False
                    with open('node_blocks' + str(self.p2p_port) + '.txt', 'r', encoding='utf8') as readfile:
                        
                        lines = readfile.readlines()
                        
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
                    conn.send(getBlocks_reply.encode('utf-8'))
                conn.close()
                
                if get_block_flag:
                   
                    self.getBlocks(get_block_hash_count, get_block_hash_begin, get_block_hash_stop)
                
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
        

