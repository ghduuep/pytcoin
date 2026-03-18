import ecdsa
import binascii
from .transaction import TxInput, TxOutput, Transaction

def generate_keys():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    private_key = binascii.hexlify(sk.to_string()).decode()
    vk = sk.get_verifying_key()
    public_key = binascii.hexlify(vk.to_string()).decode() # type: ignore
    return private_key, public_key 

class Wallet:
    def __init__(self):
        self.private_key, self.public_key = generate_keys()
    
    def get_address(self):
        return self.public_key
    
    def get_balance(self, blockchain):
        return blockchain.get_balance(self.public_key)
    
    def select_utxos(self, blockchain, amount):
        selected = []
        total = 0

        for (tx_id, idx), utxo in blockchain.utxos.items():
            if utxo.recipient == self.public_key:
                selected.append((tx_id, idx, utxo.amount))
                total += utxo.amount
                if total >= amount:
                    break
        
        if total < amount:
            return None, 0
        
        return selected, total
    
    def create_transaction(self, recipient, amount, blockchain):
        selected, total = self.select_utxos(blockchain, amount)

        if selected is None:
            return None
        
        inputs = [TxInput(tx_id, idx) for tx_id, idx, _ in selected]

        outputs = [TxOutput(recipient, amount)]

        if total > amount:
            outputs.append(TxOutput(self.public_key, total - amount))

        tx = Transaction(inputs, outputs)

        for i in range(len(inputs)):
            tx.sign_input(i, self.private_key)
        
        return tx