
class GlobalException(Exception):
    
    def __init__(self, message:str, code: int) -> None:
        self.message = message
        self.code = code
        
        
class DenyAccess(GlobalException):
    pass    

class AuthorizationHeaderRequired(GlobalException):
    pass    
    
class BodyRequestIsEmpty(GlobalException):
    pass           
     
class DeviceUnavailable(GlobalException):
    pass   
                
class FieldRequired(GlobalException):
    pass

class wireguardInterfaceExists(GlobalException):
    pass
        
class WireguardModuleNotFound(GlobalException):
    pass    
     
class WireguardConfigExist(GlobalException):
     pass
 
class PeerNotFound(GlobalException):
    pass   
    
class PeerExists(GlobalException):
    pass

class RunConfig(GlobalException):
    pass
    
    