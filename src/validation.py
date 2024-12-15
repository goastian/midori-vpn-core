from src.expetions import *
from fastapi import Request, Response
from json.decoder import JSONDecodeError
import json

class Validation():
    
    errors = list()
    
    def __init__(self) -> None:
        self.errors = []
    
    @staticmethod
    def check_authorization_header(request: Request):
        """_Checking the Authorization header_

        Args:
            request (Request): _Request_

        Raises:
            DenyAccess: _Throws an exception if the Authorization header is not provided._

        Returns:
            _str_: _token_
        """
        try: 
            return request.headers["Authorization"]
        except KeyError as e:
            raise DenyAccess("The authorization header is unavailable", 401)
       
    @staticmethod
    def check_field_is_empty_in_dict(field : str, body: dict):
        """_Check field is empty in a dict_

        Args:
            field (str): _input field_
            body (dict): _dict content_
        """
        try:
            if  field not in body:
                Validation.errors.append({ field :  f"The field {field.replace('_',' ')} is required"})
        except TypeError as e:
            Validation.errors.append({ field :  f"The field {field.replace('_',' ')} is required"})
    
    @staticmethod
    def check_field_is_empty(field: str):
        """_Checking the input field_

        Args:
            field (str): _input field_
        """         
        if field in [None, '']:
            Validation.errors.append({ field :  f"The field {field.replace('_',' ')} is required"})
        
        
    @staticmethod
    async def check_mount_validation(request: Request):
        """_Checking if the fields to mount a new interface exists_

        Args:
            request (Request): _Request_

        Raises:
            FieldRequired: _Throws an exception if the fields are empty or do not exist._" 

        Returns:
            _dict_: _Return all params_
        """
        #Reset values
        Validation.errors = []
        body = dict()
        
        try:
            #Get body content        
            body = await request.json()          
            
            Validation.check_field_is_empty_in_dict('interface_name', body) 
            Validation.check_field_is_empty_in_dict('private_key', body)
            Validation.check_field_is_empty_in_dict('listen_port', body)
            Validation.check_field_is_empty_in_dict('physical_interface', body)
            Validation.check_field_is_empty_in_dict('subnet', body)
            
            if len(Validation.errors) > 0:
                raise FieldRequired(Validation.errors, 422)
                                        
            return {
                    "interface_name": body["interface_name"],  
                    "private_key" : body["private_key"],
                    "listen_port" : body["listen_port"], 
                    "physical_interface" : body["physical_interface"],
                    "subnet" : body['subnet']
                    }
        except JSONDecodeError as e:
            Validation.check_field_is_empty_in_dict('interface_name', body) 
            Validation.check_field_is_empty_in_dict('private_key', body)
            Validation.check_field_is_empty_in_dict('listen_port', body)
            Validation.check_field_is_empty_in_dict('physical_interface', body)
            Validation.check_field_is_empty_in_dict('subnet', body)
            raise FieldRequired(Validation.errors, 422)
    
    
    @staticmethod
    async def check_umount_validation(request: Request):
        #Reset values
        Validation.errors = []
        body = dict()
        
        try:
            #Get body content        
            body = await request.json()          
            
            Validation.check_field_is_empty_in_dict('interface_name', body) 
            
            if len(Validation.errors) > 0:
                raise FieldRequired(Validation.errors, 422)
                                        
            return {"interface_name": body["interface_name"]}
        
        except JSONDecodeError as e:
            Validation.check_field_is_empty_in_dict('interface_name', body) 
            raise FieldRequired(Validation.errors, 422)
        
    
    @staticmethod
    async def check_add_peer_validation(request: Request):        
        #Reset values
        Validation.errors = []
        body = dict()
        
        try:
            body = await request.json()        
            
            Validation.check_field_is_empty_in_dict('device_name', body)
            Validation.check_field_is_empty_in_dict('interface_name', body)
            Validation.check_field_is_empty_in_dict('public_key', body)
            Validation.check_field_is_empty_in_dict('preshared_key', body)
            Validation.check_field_is_empty_in_dict('allowed_ips', body)
            Validation.check_field_is_empty_in_dict('persistent_keepalive', body)
            Validation.check_field_is_empty_in_dict('endpoint', body)
            
            if len(Validation.errors) > 0:
                raise FieldRequired(Validation.errors, 422)
            
            return {
                "device_name" : body['device_name'],
                "interface_name" : body['interface_name'],
                "public_key" : body['public_key'],
                "preshared_key" : body['preshared_key'], 
                "allowed_ips" : body['allowed_ips'],
                "persistent_keepalive" : body['persistent_keepalive'],
                "endpoint": body['endpoint']
            }
        except JSONDecodeError as e:
            Validation.check_field_is_empty_in_dict('device_name', body)
            Validation.check_field_is_empty_in_dict('interface_name', body)
            Validation.check_field_is_empty_in_dict('public_key', body)
            Validation.check_field_is_empty_in_dict('preshared_key', body)
            Validation.check_field_is_empty_in_dict('allowed_ips', body)
            Validation.check_field_is_empty_in_dict('persistent_keepalive', body)
            Validation.check_field_is_empty_in_dict('endpoint', body)
            raise FieldRequired(Validation.errors, 422)
        
        
    @staticmethod
    def check_stop_validation(interface_name: str):
        #Reset values
        Validation.errors = []
        
        try:
            Validation.check_field_is_empty(interface_name)
           
            if len(Validation.errors) > 0:
                raise FieldRequired(Validation.errors, 422)
            
        except JSONDecodeError as e:
            Validation.check_field_is_empty(interface_name)            
            raise FieldRequired(Validation.errors, 422)
        

    @staticmethod
    async def check_remove_peer(request : Request):
        Validation.errors = []
        body = dict()

        try:
            body = await request.json()        
            
            Validation.check_field_is_empty_in_dict('interface_name', body)
            Validation.check_field_is_empty_in_dict('public_key', body)  
            
            if len(Validation.errors) > 0:
                raise FieldRequired(Validation.errors, 422)
            
            return {
                "interface_name" : body['interface_name'],
                "public_key" : body['public_key']
            }
        except JSONDecodeError as e:
            Validation.check_field_is_empty_in_dict('interface_name', body)
            Validation.check_field_is_empty_in_dict('public_key', body) 
            raise FieldRequired(Validation.errors, 422)


class JsonResponser():
    
    @staticmethod
    def report_error(message, code):
        """_Report a response error_

        Args:
            message (_type_): _message_
            code (int): _status code_

        Returns:
            _JSON_: _JSon Responser_
        """
        return Response(
            content= json.dumps({"error" : message , "code" : code}), 
            status_code= code, 
            media_type= "application/json")
    
    @staticmethod  
    def report_success(message : str, code):
        """_Report a response success message_

        Args:
            message (str): _Message_
            code (int): _status code_

        Returns:
            _JSON_: _JsonResponser_
        """ 
        return Response(
            content= json.dumps({"data" : message , "code" : code}), 
            status_code= code, 
            media_type= "application/json")