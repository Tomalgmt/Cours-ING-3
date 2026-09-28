"""Neutralise le point d'entree du seul ELF audite, sans jamais l'executer.

Sans dependance Python externe. 7-Zip est necessaire pour lire/ecrire un .7z.
Exemples :
  python neutraliser_mal.py mal.7z mal-neutralise.7z --sevenzip 7z
  python neutraliser_mal.py mal.bin mal.neutralise.bin
Le resultat .7z est chiffre avec le mot de passe de laboratoire 'test'.
Une copie modifiee conserve le reste du code : destinee a l'etude en laboratoire.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

EXPECTED = '8f0bdcaabfe1089e0ea169eefeb1795bc6ea7762fff2aab0aabc60c8804dd6e2'
PATCHED = '70175ce93ed3868708f977a6b7d7e71a35c0aada00082cc66b3be2aced4c893a'
OFFSET = 0x93ba
BEFORE = bytes.fromhex('4831ed4889e7488d35')
AFTER = bytes.fromhex('31ffb83c0000000f05')

def digest(data):
    return hashlib.sha256(data).hexdigest()

def patch(data):
    if digest(data) != EXPECTED:
        raise ValueError('SHA-256 inattendu : refus de modifier une autre version du binaire.')
    if data[OFFSET:OFFSET+len(BEFORE)] != BEFORE:
        raise ValueError('Octets initiaux inattendus.')
    result = bytearray(data)
    result[OFFSET:OFFSET+len(AFTER)] = AFTER
    result = bytes(result)
    if len(result) != len(data) or digest(result) != PATCHED:
        raise ValueError('Verification du resultat echouee.')
    return result

def read_data(path, sevenzip, member):
    if path.suffix.lower() == '.7z':
        return subprocess.run([sevenzip, 'x', '-so', '-ptest', str(path), member],
                              capture_output=True, check=True).stdout
    return path.read_bytes()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--sevenzip', default=shutil.which('7z') or r'C:\Program Files\7-Zip\7z.exe')
    args = parser.parse_args()
    if args.source.resolve() == args.destination.resolve() or args.destination.exists():
        raise ValueError('Choisir un nouveau fichier : aucun original/fichier existant ne sera ecrase.')
    source = read_data(args.source, args.sevenzip, 'mal.bin')
    result = patch(source)
    if args.destination.suffix.lower() == '.7z':
        subprocess.run([args.sevenzip, 'a', '-t7z', '-mhe=on', '-ptest',
                        '-simal.neutralise.bin', str(args.destination)],
                       input=result, capture_output=True, check=True)
        reread = read_data(args.destination, args.sevenzip, 'mal.neutralise.bin')
    else:
        with args.destination.open('xb') as file:
            file.write(result)
        reread = args.destination.read_bytes()
    if digest(reread) != PATCHED:
        raise ValueError('La copie relue ne correspond pas au resultat attendu.')
    print(json.dumps({'original_sha256':digest(source), 'neutralized_sha256':digest(reread),
                      'size':len(reread), 'offset':hex(OFFSET), 'before':BEFORE.hex(),
                      'after':AFTER.hex(), 'verified_readback':True,
                      'output':str(args.destination)}, indent=2))

if __name__ == '__main__':
    main()
