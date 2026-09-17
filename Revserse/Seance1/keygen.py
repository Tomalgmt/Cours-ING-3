import lief

# Charger le binaire ELF
binaire = lief.parse("bin/license_check")

adresse_cible1 = 0x00402014
taille_secret = 10
adresse_cible2 = 0x00402008
taille_xoré = 10 

octets_secret = binaire.get_content_from_virtual_address(adresse_cible1, taille_secret)
octets_xoré = binaire.get_content_from_virtual_address(adresse_cible2, taille_xoré)


print(f"Octets bruts du secret : {bytes(octets_xoré).hex()}")
print(f"Octets bruts du xor : {bytes(octets_secret).hex()}")


texte1 = "".join(chr(c) for c in octets_secret if 32 <= c < 127)
print(f"En texte     : {texte1}")
texte2 = "".join(chr(c) for c in octets_xoré if 32 <= c < 127)
print(f"En texte     : {texte2}")

