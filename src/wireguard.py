import os, subprocess
from src.exceptions import *

class WgConfig():
    
    def __init__(self, interface_name : str) -> None:
        self.config_dir = 'config'
        self.config_file =  f"{self.config_dir}/{interface_name}.conf"
        
        #Make a directory if not exists
        if not os.path.exists(self.config_dir):
            os.mkdir(self.config_dir)
    
    def getConfigFile(self):
        """Retrieve the current config file

        Returns:
            _str_: path of file
        """
        return self.config_file
    
    def setInterface(self, private_key: str, net: str, subnet: str, address: str, listen_port: str, dns : str = None):
        """Add a new interface to the config file

        Args:
            private_key (str): Private key
            net (str): Physical network interface on the current device
            subnet (str): Subnet for this virtual wireguard network interface example(192.168.1.0/24)
            address (str): Gateway for this interface example(192.168.1.1/24)
            listen_port (str): Port to listen connections on this device
            dns (str, optional): Dns server. Default is None
        """
        with open(self.config_file, 'w') as line:
            line.write("[Interface]\n") 
            line.write(f"Address = {address}\n")
            line.write(f"PrivateKey = {private_key}\n")
            line.write(f"ListenPort = {listen_port}\n")
            line.write(f"#Subnet = {subnet}\n")
            line.write(f"#PhysicalInterface = {net}\n")
            if dns is not None:
                line.write(f"DNS = {dns}\n\n")
            else:
                line.write(f"#DNS = \n\n")
                    
    def getInterface(self):
        """Return the current interface

        Returns:
            _type_: _description_
        """
        head = ['[Interface]', '#PhysicalInterface', 'Subnet' ,'Address', 'PrivateKey', 'ListenPort', '#DNS','DNS']
        interface = list()        
        for line in self.readFile():
            if any(line.startswith(key) for key in head):
                interface.append(line)
        interface.append('\n')
        return interface
    
    def getSubnet(self):
        """Retrieve the subnet

        Returns:
            _str_: string
        """
        head = ['#Subnet']
        for line in self.readFile():
            if any(line.startswith(key) for key in head):
                return line.split('=')[1].strip()
            
    def getAddress(self):
        """Retrieve the address

        Returns:
            _str_: string
        """
        head = ['#Address']
        for line in self.readFile():
            if any(line.startswith(key) for key in head):
                return line.split('=')[1].strip()
    
    def getPhysicalInterface(self):
        """Return the current physical interface 

        Returns:
            _str_: string
        """
        head = ["#PhysicalInterface"]
        for line in self.readFile():
            if any(line.startswith(key) for key in head):
                return line.split('=')[1].strip()
            
    def getListenPort(self):
        """Retrieve the Listen port 

        Returns:
            _str_: string
        """
        for line in self.readFile():
            if line.startswith("ListenPort"):
                return line.split('=')[1].strip()
    
    def configFileExists(self):
        """Verifying existing file

        Returns:
            str: return the config file
        """
        return os.path.exists(self.config_file)
    
    def deleteConfigFile(self):
        """Delete the config file
        """
        if self.configFileExists():
            os.remove(self.config_file)
    
    def addPeer(self, user_id: str, peer:dict):
        """Add a new peer for this virtual wireguard current interface

        Args:
            user_id (str): user id 
            peer (dict): dictionary of peer with config keys
        """
        with open(self.config_file, 'a+') as file: 
            file.write("[Peer]\n")
            file.write(f"#Name = {peer.get('device_name')}\n")
            file.write(f"#User = {user_id}\n")
            file.write(f"PublicKey = {peer.get('public_key')}\n")
            file.write(f"PresharedKey = {peer.get('preshared_key')}\n")
            file.write(f"AllowedIPs = {peer.get('allowed_ips')}\n")              
            file.write(f"PersistentKeepalive = {peer.get('persistent_keepalive')}\n") 
            file.write(f"Endpoint = {peer.get('endpoint')}\n\n") 
        
    def deletePeer(self, public_key: str): 
        """Delete peer of the system

        Args:
            public_key (str): public key of the peer

        Returns:
            _boolean_: True is remove and False does not remove
        """
        content = list()        
        content.append(self.getInterface())    #Add interface  
        peers = self.getPeers()        # get peers
                
        for peer in self.getPeers():
            if any(public_key in line for line in peer) and any('PublicKey' in line for line in peer):
                peers.remove(peer)          
                content.extend(peers)
                
                with open(self.config_file, 'w') as file:
                    file.write(self.changeListToString(content))                    
                return True
            
        return False

    def readFile(self):
        """Read the file content

        Returns:
            _type_: _description_
        """
        file_content = list()      
        with open(self.config_file, 'r') as line:
            file_content = line.readlines()
        return file_content  
    
    def getPeers(self):
        interface_peers = [key for key in self.readFile() if any(substring in key for substring in ['Peer', 'Name', 'User', 'PublicKey','AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey'])]
        
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
    
    def peerExists(self, value: str):
        for peer in self.getPeers():
            if value in ''.join(peer):
                return True
        return False
        
    def findPeer(self, value: str):
        for peer in self.getPeers():
            if value in ''.join(peer):
                return peer
        return False
    
    def searchPeers(self, value: str):         
        for peer in self.getPeers():
            if value in ''.join(peer):
                yield peer
                
    def changeListToString(self, content: list):
        data = list()
        for item in content:
            data.append("".join(item))
        return "".join(data)
    
    def setDNS(self):
        pass 
    
    def getPrivateKey(self):
        pass
    
    
    @staticmethod
    def loadConfigFile(config_file):
        if os.path.exists(config_file): 
            try:
                subprocess.run(['wg-quick','up', config_file], check= True, capture_output = True).stdout
                return [f"Network Interface run successfully", 201]
            except subprocess.CalledProcessError as e:
                raise RunConfig("Can not run the config file", 403)
    
    @staticmethod
    def cleanNetworkLink(link: str):
        return link.split("@")[0]
    
    @staticmethod
    def deleteSubnetPrefix(subnet: str):
        return subnet.split("/")[0]