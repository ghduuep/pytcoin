import time
import json
import hashlib
import ecdsa
import binascii

class TxOutput:
    def __init__(self, recipient, amount):
        self.recipient = recipient
        self.amount = amount

class TxInput:
    def __init__(self, tx_id, output_index, signature=None, public_key=None):
        self.tx_id = tx_id
        self.output_index = output_index
        self.signature = signature
        self.public_key = public_key

class Transaction:
    def __init__(self, inputs, outputs):
        self.inputs = inputs
        self.outputs = outputs
        self.timestamp = time.time()
        self.signature = None

    def compute_hash(self):
        data = json.dumps(self.__dict__, default=lambda o: o.__dict__, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    def compute_hash_for_signing(self):
        data = {
            "inputs": [(i.tx_id, i.output_index) for i in self.inputs],
            "outputs": [(o.recipient, o.amount) for o in self.outputs],
            "timestamp": self.timestamp
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    
    def sign_transaction(self, private_key_hex):
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)
        self.signature = sk.sign(self.compute_hash().encode()).hex()

    def sign_input(self, input_index, private_key_hex):
        tx_input = self.inputs[input_index]

        sk = ecdsa.SigningKey.from_string(
            bytes.fromhex(private_key_hex),
            curve=ecdsa.SECP256k1
        )

        message = self.compute_hash_for_signing().encode()
        signature = sk.sign(message)

        tx_input.signature = signature.hex()
        tx_input.public_key = binascii.hexlify(
            sk.get_verifying_key().to_string() #type: ignore
        ).decode()


    
