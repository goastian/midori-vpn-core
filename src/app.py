#!env/bin/python
from fastapi import FastAPI, Request 
from src.oauth2_server import   Authorization
from src.expetions import *
from json.decoder import JSONDecodeError
from src.validation import Validation, JsonResponser
try:
    from src.wireguard import WgCore, wireguardInterfaceExists
except ModuleNotFoundError as e:
    raise WireguardModuleNotFount(f"{ e.msg } . This module is owned by Astian Inc and is not yet available to the general public.", 404)
    
    
    
    
app = FastAPI()
    
@app.post("/api/wireguard/mount")
async def mount(request: Request):
    """_Create and mount a new Wireguard Network Interface_

    Args:
        request (Request): _Request_

    Raises:
        JSONDecodeError: _If the json decode is invalid_
        wireguardInterfaceExists: _If the Wireguard Network Interface exists_
        DenyAccess: _If the user does not have the access right_
        FieldRequired: _If the field is empty_

    Returns:
        _Response_: _response data_
    """
      
    try:               
        Authorization.check_scope(
            Validation.check_authorization_header(request), 
            'vpn_admin') 
        
        body = await Validation.check_mount_validation(request)    
        response, code = WgCore.add_interface(body)
        return JsonResponser.report_success(response, code)
     
    except JSONDecodeError as e:         
        return JsonResponser.report_error(e.msg, 422)   
    except wireguardInterfaceExists as e:
        return JsonResponser.report_error(e.message, e.code)
    except DenyAccess as e:
        return JsonResponser.report_error(e.message, e.code)
    except FieldRequired as e:
        return JsonResponser.report_error(e.message, e.code)
         
     

@app.delete("/api/wireguard/umount")
async def umount(request: Request):
    """_summary_

    Args:
        request (Request): _Request_

    Raises:
        JSONDecodeError: _If the json decode is invalid_
        DenyAccess: If the user does not have the access right
        DeviceUnavailable: _If the device is not available_

    Returns:
        _Response_: _response data_

    """
    try:
        #Checking authorization        
        token = Validation.check_authorization_header(request)       
        Authorization.check_scope(token, 'vpn_admin')
        
        #Get body content
        body = await Validation.check_umount_validation(request)
        response, code = WgCore.delete_interface(body)        
        return JsonResponser.report_success(response, code)
    
    except JSONDecodeError as e:         
        return JsonResponser.report_error(e.msg, 422) 
    except DenyAccess as e:
        return JsonResponser.report_error(e.message, e.code)
    except DeviceUnavailable as e:
        return JsonResponser.report_error(e.message, e.code)
    except FieldRequired as e:
        return JsonResponser.report_error(e.message, e.code)
             
    
@app.get("/api/wireguard/down/{interface_name}")
async def down(interface_name: str, request: Request):
    """Stop Wireguard interface

    Args:
        interface_name (str): Connection name
    """ 
    try:
        #Checking authorization        
        token = Validation.check_authorization_header(request)     
        Authorization.check_scope(token, 'vpn_admin')   
                 
        response, code = WgCore.stop_interface(interface_name)
        return JsonResponser.report_success(response, code)
    except DenyAccess as e:
        return JsonResponser.report_error(e.message, e.code)
    except DeviceUnavailable as e:
        return JsonResponser.report_error(e.message, e.code)
        
      
@app.get("/api/wireguard/up/{interface_name}")
async def up(interface_name: str, request: Request):
    """Start wireguard interface

    Args:
        interface_name (str): Connection name
    """
    try:
        #Checking authorization        
        token = Validation.check_authorization_header(request)   
        Authorization.check_scope(token, 'vpn_admin')
    
        response, code = WgCore.start_interface(interface_name)
        return JsonResponser.report_success(response, code)
    
    except DenyAccess as e:
        return JsonResponser.report_error(e.message, e.code)
    except DeviceUnavailable as e:
        return JsonResponser.report_error(e.message, e.code)
     
@app.post("/api/wireguard/peer/add")
async def store(request: Request):
    """_summary_
    Args:
        request (Request): _description_

    Returns:
        _type_: _description_
    """
     
    try:        
        #Checkin scopes 
        token = Validation.check_authorization_header(request)        
        Authorization.check_basic_authentication(token)        
        
        body = await Validation.check_add_peer_validation(request)        
        response, code =  WgCore.add_peer(body)
        
        return JsonResponser.report_success(response, code)
    
    except JSONDecodeError as e:         
        return JsonResponser.report_error(e.msg, 422)
    except DenyAccess as e:
        return JsonResponser.report_error(e.message, e.code)
    except FieldRequired as e:
        return JsonResponser.report_error(e.message, e.code)
    except DeviceUnavailable as e:
        return JsonResponser.report_error(e.message, e.code)

    
@app.delete("/api/wireguard/peer/delete")
async def destroy(request: Request): 
    """_summary_

    Args:
        request (Request): _description_

    Raises:
        HTTPException: _description_
        HTTPException: _description_

    Returns:
        _type_: _description_
    """
    try:
        #Checning scopes
        token = Validation.check_authorization_header(request)        
        Authorization.check_basic_authentication(token)
        
        #Get body content
        body = await Validation.check_remove_peer(request)        
        response, code = WgCore.remove_peer(body)
    
        return  JsonResponser.report_success(response, code)
    
    except JSONDecodeError as e:         
        return JsonResponser.report_error(e.msg, 422)
    except DenyAccess as e:
        return JsonResponser.report_error(e.message, e.code) 
    except FieldRequired as e:
        return JsonResponser.report_error(e.message, e.code)
    except DeviceUnavailable as e:
        return JsonResponser.report_error(e.message, e.code)


@app.get("/api/system/network-interfaces")
async def get_interfaces(request: Request):
    """Return all Network Interfaces available
    """
    try:
        #Checking authorization        
        token = Validation.check_authorization_header(request)         
        Authorization.check_scope(token, 'vpn_admin')
        
        return JsonResponser.report_success(WgCore.list_network_interfaces(), 200)
    
    except DenyAccess as e:
        return JsonResponser.report_error(e.message, e.code)