from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
import pickle

def cpabe_encrypt(aes_key_bytes, policy, public_key_file, output_file_path):
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)

    # Load public key đã serialize
    with open(public_key_file, "rb") as f:
        pk_serialized = pickle.load(f)
    pk = {k: group.deserialize(v) for k, v in pk_serialized.items()}

    # Mã hóa AES key (dạng bytes) theo policy
    ct = cpabe.encrypt(pk, aes_key_bytes, policy)

    # Lưu ciphertext (pickle) ra file
    with open(output_file_path, "wb") as f:
        pickle.dump(ct, f)

    return output_file_path
