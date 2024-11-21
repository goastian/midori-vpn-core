import os
from src.expetions import *

class WgConfig():
         
    def __init__(self, interface_name : str) -> None:
        self.config_dir = 'config'
        self.config_file =  f"{self.config_dir}/{interface_name}.conf"
        
        #Make a directory if not exists
        if not os.path.exists(self.config_dir):
            os.mkdir(self.config_dir)
    
    def set_interface(self, private_key: str, address: str, listen_port: str, dns : str = None):
        with open(self.config_file, 'w') as line:
            line.write("[Interface]\n") 
            line.write(f"PrivateKey = {private_key}\n")
            line.write(f"#Address = {address}\n")
            line.write(f"ListenPort = {listen_port}\n")
            if dns is not None:
                line.write(f"DNS = {dns}\n\n")
            else:
                line.write(f"#DNS = \n\n")
                    
    def get_interface(self):
        """Get Wireguard Interface

        Returns:
            _type_: list()
        """
        head = ['[Interface]', '#Address', 'Address' ,'PrivateKey', 'ListenPort', '#DNS','DNS']
        interface = list()        
        for line in self.read_file():
            if any(line.startswith(key) for key in head):
                interface.append(line)
        interface.append('\n')
        return interface
    
    def get_interface_address(self):
        head = ["Address", "#Address"]
        for line in self.read_file():
            if any(line.startswith(key) for key in head):
                return line.split('=')[1].strip()
            
    def get_interface_listen_port(self):
        for line in self.read_file():
            if line.startswith("ListenPort"):
                return line.split('=')[1].strip()
    
    def config_file_exists(self):
        return os.path.exists(self.config_file)
    
    def remove_config_file(self):
        if self.config_file_exists():
            os.remove(self.config_file)
    
    def add_peer(self, user_id: str, peer:dict):
        with open(self.config_file, 'a+') as file: 
            file.write("[Peer]\n")
            file.write(f"#Name = {peer.get('device_name')}\n")
            file.write(f"#User = {user_id}\n")
            file.write(f"PublicKey = {peer.get('public_key')}\n")
            file.write(f"PresharedKey = {peer.get('preshared_key')}\n")
            file.write(f"AllowedIPs = {peer.get('allowed_ips')}\n")              
            file.write(f"PersistentKeepalive = {peer.get('persistent_keepalive')}\n") 
            file.write(f"Endpoint = {peer.get('endpoint')}\n\n") 
        
    def remove_peer(self, value: str):       
        """Remove peers 
        Args:
            index (_type_): Any
        """
        content = list()        
        content.append(self.get_interface())    #Add interface  
        peers = self.get_peers()        # get peers
                
        for peer in self.get_peers():
            if any(value in line for line in peer) and any('PublicKey' in line for line in peer):
                peers.remove(peer)          
                content.extend(peers)
                
                with open(self.config_file, 'w') as file:
                    file.write(self.change_list_to_string(content))                    
                return True
            
        return False
             
    def read_file(self):
        file_content = list()      
        with open(self.config_file, 'r') as line:
            file_content = line.readlines()
        return file_content  
    
    def get_peers(self):
        interface_peers = [key for key in self.read_file() if any(substring in key for substring in ['Peer', 'Name', 'User', 'PublicKey','AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey'])]
        
        peers = []
        current_peer = []
        for line in interface_peers:
            if line.startswith('[Peer]'):
                if current_peer:     
                    current_peer.append('\n')              
                    peers.append(current_peer.copy())                     
                    current_peer.clear()
            current_peer.append(line)

        if current_peer:
            current_peer.append('\n')
            peers.append(current_peer)
              
        return peers
    
    def peer_exists(self, value: str):
        for peer in self.get_peers():
            if value in ''.join(peer):
                return True
        return False
        
    def find_peer(self, value: str):
        for peer in self.get_peers():
            if value in ''.join(peer):
                return peer
        return False
    
    def search_peers(self, value: str):         
        for peer in self.get_peers():
            if value in ''.join(peer):
                yield peer
                
    def change_list_to_string(self, content: list):
        data = list()
        for item in content:
            data.append("".join(item))
        return "".join(data)
     
    def set_dns(self):
        pass 
    
    def get_port(self):
        pass
    
    def get_private_key(self):
        pass
    
    