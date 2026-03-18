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
    
    def sign_transaction(self, private_key_hex):
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)
        self.signature = sk.sign(self.compute_hash().encode()).hex()

    def sign_input(self, input_index, private_key_hex):
        tx_input = self.inputs[input_index]

        sk = ecdsa.SigningKey.from_string(
            bytes.fromhex(private_key_hex),
            curve=ecdsa.SECP256k1
        )

        message = self.compute_hash().encode()
        signature = sk.sign(message)

        tx_input.signature = signature.hex()
        tx_input.public_key = binascii.hexlify(
            sk.get_verifying_key().to_string() #type: ignore
        ).decode()


    
