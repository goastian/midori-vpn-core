from typing import Any
import dotenv
import requests
import os 
from src.exceptions import * 

dotenv.load_dotenv()
        
class Authorization():
    
    @staticmethod
    def check_scope(token:str, scope: str):
        """Checking the user has a scope

        Args:
            token (str): _Bearer token_
            scope (str): _Scope for this user_

        Raises:
            DenyAccess: _description_
        """
        API = os.getenv('AUTHORIZATION_SERVER')
        response = requests.get(f"{API}/api/gateway/check-scope",
                                verify=False,
                                headers= { 
                                        'Authorization' : token, 
                                        "X-SCOPES": scope,
                                        "Accept" : "application/json"
                                        })
        
        if response.status_code == 200:
            pass
        elif response.status_code == 401:
            raise DenyAccess("The client must authenticate itself to get the requested response", 401)
        elif response.status_code == 403:
            raise DenyAccess("The client does not have access rights to the content", 403)
    
    
    def check_scopes(token: str, scopes: list):
        """Checking the user has a scope

        Args:
            token (str): _Bearer token_
            scope (str): _Scope for this user_

        Raises:
            DenyAccess: _description_
        """
        
        API = os.getenv('AUTHORIZATION_SERVER')
        response = requests.get(f"{API}/api/gateway/check-scope",
                                verify=False,
                                headers= { 
                                        'Authorization' : token, 
                                        "X-SCOPES": ','.join(scopes)
                                        })
        
        if response.ok:
            pass
        elif response.status_code == 401:
            raise DenyAccess("The client must authenticate itself to get the requested response", 401)
        elif response.status_code == 403:
            raise DenyAccess("The client does not have access rights to the content", 403)
    
    
    @staticmethod
    def check_basic_authentication(token: str):
        """Checking the token is valid

        Args:
            token (str): _Bearer token_
        """
        API = os.getenv('AUTHORIZATION_SERVER')
        response = requests.get(f"{API}/api/gateway/check-authentication",
                                verify=False,
                                headers= {'Authorization' : token})
        
        if response.ok:
            pass
        elif response.status_code == 401:
            raise DenyAccess("The client must authenticate itself to get the requested response", 401)
        elif response.status_code == 403:
            raise DenyAccess("The client does not have access rights to the content", 403)
    
    
    @staticmethod
    def get_authenticated_user(token: str):
        API = os.getenv('AUTHORIZATION_SERVER')
        response = requests.get(f"{API}/api/gateway/user",
                                verify=False,
                                headers= {'Authorization' : token})
        
        if response.ok:
            return response.json()
        elif response.status_code == 401:
            raise DenyAccess("The client must authenticate itself to get the requested response", 401)
        elif response.status_code == 403:
            raise DenyAccess("The client does not have access rights to the content", 403)

class vpnControl():    
    
    @staticmethod
    def checkNumberOfDevices(token:str):
        API = os.getenv('CONTROL_SERVER')
        response = requests.get(f"{API}/api/peers",
                                verify=False,
                                headers= { 
                                        'Authorization' : token,  
                                        "Accept" : "application/json"
                                        })
        
    
        if response.status_code == 200:
            data = response.json()
            # Working in process
        elif response.status_code == 401:
            raise DenyAccess("The client must authenticate itself to get the requested response", 401)
        elif response.status_code == 403:
            raise DenyAccess("The client does not have access rights to the content", 403)
    
    