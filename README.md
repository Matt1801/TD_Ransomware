# TD_Ransomware
Date butoir : 11 avril 2023 23h59
## Chiffrement
**Q1) Quelle est le nom de l'algorithme de chiffrement ? Est-il robuste et pourquoi ?**

Le chiffrement XOR est une méthode de chiffrement symétrique basée sur l'utilisation de l'opérateur logique XOR. Le chiffrement utilise les données en clair et la clé qu'il va associé en applicant la table XOR sur chaque bit de la clé associé à chaque bit des données.

| Data  | Clé | XOR |
| :-: |:-:| :-:|
| 0 | 0 | 0 |
| 0 | 1 | 1 |
| 1 | 0 | 1 |
| 1 | 1 | 0 |

Donc avec une data codé sur 4 bits tel que 0011 et une clé codé sur 4 bits tel que 0101 on obtient le message chiffré 0110.
Ce type de chiffrement est considéré comme peu robuste car peut être contré par les attaques de forçage en essayant des clés jusqu'à obtenir la clé correcte.

## Génération des secrets
**Q2) Pourquoi ne pas hacher le sel et la clef directement ? Et avec un hmac ?**
Il ne faut pas hacher directement le ainsi que la clé car la dérivation sera trop faible tandis que la méthode PBKDF2HMAC perrmet d'assurer une protection face aux attaques de type "brute forcing" en ajoutant de la complexité. De plus, la fonction peut devenir plus sécurisé simplement en augmentant le nombre d'itérations.

## Setup
**Q3) Pourquoi il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent ?**
Tout d'abord, cette vérification permet d'optimiser l'exécution. En effet, recréer des données serait une perte de temps. De plus, le fait d'écraser le token orécédent complexifierai la récupération des données voir la rendrait impossible avec ce dernier.

## Vérifier et utiliser la clef
**Q4) Comment vérifier que la clef la bonne ?**
Afin de vérifier si la clé est la bonne nous pouvons effectuer une nouvelle dérivation avec cette nouvelle clé. En cas de correspondance entre les dérivations nous pouvons estimé que la clé est la bonne.