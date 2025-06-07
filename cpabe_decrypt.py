from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
import pickle

def cpabe_decrypt(encrypted_key_file, secret_key_file, public_key_file):
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)

    # Load public key
    with open(public_key_file, "rb") as f:
        pk = pickle.load(f)
        pk = {k: group.deserialize(v) for k, v in pk.items()}

    # Load secret key
    with open(secret_key_file, "rb") as f:
        sk = pickle.load(f)
        sk = {k: group.deserialize(v) for k, v in sk.items()}

    # Load encrypted AES key
    with open(encrypted_key_file, "rb") as f:
        ct = pickle.load(f)
        ct = {k: group.deserialize(v) if isinstance(v, bytes) else v for k, v in ct.items()}

    aes_key = cpabe.decrypt(pk, sk, ct)
    return aes_key
