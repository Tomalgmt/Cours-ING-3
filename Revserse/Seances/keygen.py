import lief

# Charger le binaire ELF
binaire = lief.parse("bin/license_check")

# ici on a des variables locales pour le programme
adresse_cible1 = 0x00402014
taille_secret = 10
adresse_cible2 = 0x00402008
taille_xoré = 10 

# ici on recupère la ligne a partir d'une adresse et une taille en octets
octets_secret = binaire.get_content_from_virtual_address(adresse_cible1, taille_secret)
octets_xoré = binaire.get_content_from_virtual_address(adresse_cible2, taille_xoré)

# on transforme en hex
print(f"Octets bruts du secret  : {bytes(octets_xoré).hex()}")
print(f"Octets bruts du xor     : {bytes(octets_secret).hex()}")

# ici on transforme le hex en texte ascii
texte1 = "".join(chr(c) for c in octets_secret if 32 <= c < 127)
print(f"En texte     : {texte1}")
texte2 = "".join(chr(c) for c in octets_xoré if 32 <= c < 127)
print(f"En texte     : {texte2}")

# on fait un XOR octet par octet entre le secret et la valeur XOR
# zip permet de parcourir les deux tableaux en même temps
resultat_xor = bytes(
    a ^ b
    for a, b in zip(octets_secret, octets_xoré)
)

# on affiche le résultat du XOR sous forme hexadécimale
print(f"Clé de la license en hex    : {resultat_xor.hex()}")

# on transforme chaque octet du résultat XOR en caractère ASCII
# si le caractère n'est pas affichable, on le remplace par un "."
texte_xor = "".join(
    chr(c) if 32 <= c < 127 else "."
    for c in resultat_xor
)

# on affiche le résultat final du XOR sous forme de texte
print(f"Clé de la license en texte  : {texte_xor}")
