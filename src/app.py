from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from src.oauth2_server import   Authorization
from src.exceptions import *
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
    return JsonResponser.reportError(e.message,  e.code)


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
    token = Validation.checkAuthorizationHeader(request)
    Authorization.check_scope(token,'admin')
    
    body = await Validation.checkMountValidation(request)    
    response, code = WgCore.addInterface(body)
    return JsonResponser.reportSuccess(response, code)

@app.delete("/api/wireguard/umount")
async def umount(request: Request):   
    """Remove Interface

    Args:
        request (Request): request

    Returns:
        _json_: json
    """
    #Checking authorization        
    token = Validation.checkAuthorizationHeader(request)       
    Authorization.check_scope(token, 'admin')
    
    #Get body content
    body = await Validation.checkUmountValidation(request)
    response, code = WgCore.deleteInterface(body)        
    return JsonResponser.reportSuccess(response, code)    
    
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
    token = Validation.checkAuthorizationHeader(request)     
    Authorization.check_scope(token, 'admin')   
    
    response, code = WgCore.stopInterface(interface_name)
    return JsonResponser.reportSuccess(response, code)
    
    
@app.get("/api/wireguard/up/{interface_name}")
async def up(interface_name: str, request: Request):     
    token = Validation.checkAuthorizationHeader(request)   
    Authorization.check_scope(token, 'admin')

    response, code = WgCore.start_interface(interface_name)
    return JsonResponser.reportSuccess(response, code)

@app.post("/api/wireguard/peer/add")
async def store(request: Request):
    """Add new peer

    Args:
        request (Request): request

    Returns:
        _json_: json
    """
    #Checking scopes 
    token = Validation.checkAuthorizationHeader(request)           
    Authorization.check_scope(token, 'vpn-free')    
    user_id = Authorization.get_authenticated_user(token).get('id')

    body = await Validation.checkAddPeerValidation(request)       
    response, code =  WgCore.addPeer(user_id, body)    
    return JsonResponser.reportSuccess(response, code)
    
    
@app.delete("/api/wireguard/peer/delete")
async def destroy(request: Request):
    #Checking scopes
    token = Validation.checkAuthorizationHeader(request)        
    Authorization.check_basic_authentication(token)
    
    #Get body content
    body = await Validation.checkRemovePeer(request)        
    response, code = WgCore.deletePeer(body)
    return  JsonResponser.reportSuccess(response, code)

@app.get("/api/system/network-interfaces")
async def getInterfaces(request: Request):
    """Show all physical network interface

    Args:
        request (Request): request

    Returns:
        _json_: json
    """
    #Checking authorization    
    token = Validation.checkAuthorizationHeader(request)         
    Authorization.check_scope(token, 'admin')
    return JsonResponser.reportSuccess(WgCore.listNetworkInterfaces(), 200)

@app.post("/api/system/reload-networks")
async def reloadNetworks(request: Request):
    token = Validation.checkAuthorizationHeader(request)        
    Authorization.check_scope(token, 'admin')
    
    body = await request.json() 
    [response , code ] = WgCore.reloadInterfaces(body['name'])
    return JsonResponser.reportSuccess(response, code)

@app.post("/api/system/firewall-reset")
async def firewallReset(request: Request):
    token = Validation.checkAuthorizationHeader(request)        
    Authorization.check_scope(token, 'admin')
    
    [response , code ] = WgCore.prepareFirewall()
    return JsonResponser.reportSuccess(response, code)