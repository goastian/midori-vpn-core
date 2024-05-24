
class DenyAccess(Exception):
    
    def __init__(self, message:str, code: int) -> None:
        self.message = message
        self.code = code

class AuthorizationHeaderRequired(Exception):
    
    def __init__(self, message:str, code: int) -> None:
        self.message = message
        self.code = code

class BodyRequestIsEmpty(Exception):
           
    def __init__(self,  message:str, code: int) -> None:
        self.message = message
        self.code = code

class DeviceUnavailable(Exception):
    
    def __init__(self,  message:str, code: int) -> None:
        self.message = message
        self.code = code
                
class FieldRequired(Exception):
    
    def __init__(self,  message , code: int) -> None:
        self.message = message
        self.code = code
        
class wireguardInterfaceExists(Exception):
    
    def __init__(self, message, code) -> None: 
        self.message = message
        self.code = code
        
    def __str__(self) -> str:
        return self.message
    


                
    