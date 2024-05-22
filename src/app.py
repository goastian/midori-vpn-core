#!env/bin/python
from fastapi import FastAPI, Request, HTTPException 
from src.wireguard import WgCore, wireguardInterfaceExists
from src.oauth2_server import DenyAccess, Authorization
import json

app = FastAPI()
    
@app.post("/api/wireguard/mount")
async def mount(request: Request):
    """Create a new wireguard network interface 
    
    Args:
        name (str): _Wireguard interface name , example (wgtest)_,
        gateway (str): _Gateway interface name, example (10.0.0.1/8)_
        private_key (str): _Private Network interface key_
        out_interface (str): _Interface network, example (wlan0, eth0)_
    """   
    try:        
        #Checking authorization        
        headers = request.headers 
        token = headers["Authorization"]        
        Authorization.check_scope(token, 'vpn_admin')
         
        #Get body content
        body = await request.json()
        name = body['name']
        gateway = body['gateway']
        private_key = body['private_key']
        out_interface = body['out_interface']
                
        return  WgCore.add_interface(
                                name = name, 
                                gateway = gateway, 
                                private_key = private_key, 
                                out_interface = out_interface
                                )

    except json.decoder.JSONDecodeError as e:         
        raise HTTPException(status_code=422, detail= e)     
    except wireguardInterfaceExists as e:
        return  HTTPException(status_code=422, detail= e.message)  
    except DenyAccess as e:
        return HTTPException(status_code=e.code, detail= e.message)

@app.delete("/api/wireguard/umount")
async def umount(request: Request):
    """Remove a Wireguard network interface

    Args:
        interface_name (str):Wireguard interface name
        out_interface (str): Out network interface 
    """
    try:
        #Checking authorization        
        headers = request.headers 
        token = headers["Authorization"]        
        Authorization.check_scope(token, 'vpn_admin')
        
        #Get body content
        body = await request.json()
        interface_name = body['interface_name']
        out_interface = body['out_interface']
        
        return WgCore.delete_interface(interface_name, out_interface)
    
    except json.decoder.JSONDecodeError as e:         
        raise HTTPException(status_code=422, detail= e) 
    except DenyAccess as e:
        return HTTPException(status_code=e.code, detail= e.message)
    
    
@app.get("/api/wireguard/down/{interface_name}")
async def down(interface_name: str, request: Request):
    """Stop Wireguard interface

    Args:
        interface_name (str): Connection name
    """ 
    try:
        #Checking authorization        
        headers = request.headers 
        token = headers["Authorization"]        
        Authorization.check_scope(token, 'vpn_admin')   
                 
        return WgCore.stop_interface(interface_name)
    except DenyAccess as e:
        return HTTPException(status_code=e.code, detail= e.message)
      
      
@app.get("/api/wireguard/up/{interface_name}")
async def up(interface_name: str, request: Request):
    """Start wireguard interface

    Args:
        interface_name (str): Connection name
    """
    try:
        #Checking authorization        
        headers = request.headers 
        token = headers["Authorization"]        
        Authorization.check_scope(token, 'vpn_admin')
    
        return WgCore.start_interface(interface_name)
    except DenyAccess as e:
        return HTTPException(status_code=e.code, detail= e.message)

     
@app.post("/api/wireguard/peer/add")
async def store(request: Request):
    """Add new peer into wireguard interface

    Args:
        interface_name (str) = _Wireguard Name Network Interface_
        public_key (str) = _Public Client key_
        allowed_ips (str) = _Ip address_
        preshared_key (str) = _preshared key_
        persistent_keepalive (srt) = _response time_
        endpoint (str) = _host ip_
    """
    try:
        
        #Checkin scopes 
        headers = request.headers 
        token = headers["Authorization"]        
        Authorization.check_basic_authentication(token)
        
        #Get body content
        body = await request.json()
        interface_name = body['interface_name']    
        public_key = body['public_key'] 
        preshared_key = body['preshared_key'] 
        allowed_ips = body['allowed_ips']
        persistent_keepalive = body['persistent_keepalive']
        endpoint = body['endpoint']
        
        return WgCore.add_peer(
                            interface_name=interface_name, 
                            public_key = public_key, 
                            preshared_key = preshared_key, 
                            allowed_ips= allowed_ips, 
                            endpoint= endpoint,
                            persistent_keepalive = persistent_keepalive
                        )
    except json.decoder.JSONDecodeError as e:         
        raise HTTPException(status_code=422, detail= e) 
    except DenyAccess as e:
        return HTTPException(status_code=e.code, detail= e.message)


@app.delete("/api/wireguard/peer/delete")
async def destroy(request: Request):
    """Remove peer

    Args:
        interface_name (str): _Interface Name_
        public_key (srt): _Public key_
    """
    try:
        #Checning scopes
        headers = request.headers 
        token = headers["Authorization"]        
        Authorization.check_basic_authentication(token)
        
        #Get body content
        body = await request.json()
        interface_name = body['interface_name']
        public_key = body["public_key"]
    
        return WgCore.remove_peer(interface_name, public_key)
    except json.decoder.JSONDecodeError as e:         
        raise HTTPException(status_code=422, detail= e) 
    except DenyAccess as e:
        return HTTPException(status_code=e.code, detail= e.message)


@app.get("/api/system/network-interfaces")
async def get_interfaces(request: Request):
    """Return all Network Interfaces available
    """
    try:
        #Checking authorization        
        headers = request.headers 
        token = headers["Authorization"]        
        Authorization.check_scope(token, 'vpn_admin')
        
        return WgCore.list_network_interfaces()
    
    except DenyAccess as e:
        return HTTPException(status_code=e.code, detail= e.message)