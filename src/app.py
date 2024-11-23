from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from src.oauth2_server import   Authorization
from src.expetions import *
from json.decoder import JSONDecodeError
from src.validation import Validation, JsonResponser 
try:
    from src.core import WgCore, wireguardInterfaceExists
except ModuleNotFoundError as e:
    raise WireguardModuleNotFound(f"{ e.msg } . This module is owned by @ELyerr. and is not yet available to the general public.", 404)
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
    
app = FastAPI(
    docs_url=None, 
    redoc_url=None,  
    openapi_url=None 
    )
templates = Jinja2Templates(directory="templates/errors")
#app.mount("/static", StaticFiles(directory="static"), name="static")


@app.exception_handler(GlobalException)
async def custom_api_exception_handler(request: Request, e: GlobalException):
    return JsonResponser.report_error(e.message,  e.code)


@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    return templates.TemplateResponse("404.html", {"request": request}, status_code=404)


@app.post("/api/wireguard/mount")
async def mount(request: Request):
    """Mount interface 

    Args:
        request (Request): request

    Returns:
        _type_: _description_
    """
    token = Validation.check_authorization_header(request)
    Authorization.check_scope(token,'vpn_admin')
    
    body = await Validation.check_mount_validation(request)    
    response, code = WgCore.add_interface(body)
    return JsonResponser.report_success(response, code)         
     

@app.delete("/api/wireguard/umount")
async def umount(request: Request):   
    """Remove Interface

    Args:
        request (Request): request

    Returns:
        _json_: json
    """
    #Checking authorization        
    token = Validation.check_authorization_header(request)       
    Authorization.check_scope(token, 'vpn_admin')
    
    #Get body content
    body = await Validation.check_umount_validation(request)
    response, code = WgCore.delete_interface(body)        
    return JsonResponser.report_success(response, code)    
             
    
@app.get("/api/wireguard/down/{interface_name}")
async def down(interface_name: str, request: Request): 
    """Shutdown interface

    Args:
        interface_name (str): Interface Name
        request (Request): request

    Returns:
        _json_: json
    """
    #Checking authorization        
    token = Validation.check_authorization_header(request)     
    Authorization.check_scope(token, 'vpn_admin')   
    
    response, code = WgCore.stop_interface(interface_name)
    return JsonResponser.report_success(response, code)
    
      
@app.get("/api/wireguard/up/{interface_name}")
async def up(interface_name: str, request: Request):
    """Start interface

    Args:
        interface_name (str): Interface Name
        request (Request): request

    Returns:
        _json_: json
    """
    #Checking authorization        
    token = Validation.check_authorization_header(request)   
    Authorization.check_scope(token, 'vpn_admin')

    response, code = WgCore.start_interface(interface_name)
    return JsonResponser.report_success(response, code)

         
@app.post("/api/wireguard/peer/add")
async def store(request: Request):
    """Add new peer

    Args:
        request (Request): request

    Returns:
        _json_: json
    """
    #Checking scopes 
    token = Validation.check_authorization_header(request)        
    Authorization.check_basic_authentication(token)       
    user_id = Authorization.get_authenticated_user(token).get('id')

    body = await Validation.check_add_peer_validation(request)          
    response, code =  WgCore.add_peer(user_id, body)    
    return JsonResponser.report_success(response, code)
    
   
    
@app.delete("/api/wireguard/peer/delete")
async def destroy(request: Request):
    #Checking scopes
    token = Validation.check_authorization_header(request)        
    Authorization.check_basic_authentication(token)
    
    #Get body content
    body = await Validation.check_remove_peer(request)        
    response, code = WgCore.remove_peer(body)
    return  JsonResponser.report_success(response, code)
 

@app.get("/api/system/network-interfaces")
async def get_interfaces(request: Request):
    """Show all physical network interface

    Args:
        request (Request): request

    Returns:
        _json_: json
    """
    #Checking authorization    
    token = Validation.check_authorization_header(request)         
    Authorization.check_scope(token, 'vpn_admin')
    return JsonResponser.report_success(WgCore.list_network_interfaces(), 200)

@app.post("/api/system/reload-networks")
async def reload_wgs(request: Request):
    token = Validation.check_authorization_header(request)        
    Authorization.check_scope(token, 'vpn_admin')
    
    body = await request.json() 
    [response , code ] = WgCore.reload_interfaces(body['name'])
    return JsonResponser.report_success(response, code)