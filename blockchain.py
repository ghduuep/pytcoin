import hashlib
import time
import json
import ecdsa
import binascii

def generate_keys():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    private_key = binascii.hexlify(sk.to_string()).decode()
    vk = sk.get_verifying_key()
    public_key = binascii.hexlify(vk.to_string()).decode() # type: ignore
    return private_key, public_key

class Block:
    def __init__(self, index, transactions, previous_hash, nonce=0):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
class Blockchain:

    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.create_genesis_block()
        self.difficulty = 4
        self.mining_reward = 50

    def create_genesis_block(self):
        genesis_block = Block(0, [], "0")
        self.chain.append(genesis_block)
    
    def add_block(self, block):
        block.hash = self.proof_of_work(block)
        if block.previous_hash == self.chain[-1].hash:
            self.chain.append(block)
        else:
            print("Invalid block. Previous hash does not match.")
    
    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * self.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash
    
    def add_transaction(self, transaction):
        if transaction.is_valid():
            self.pending_transactions.append(transaction)
        else:
            print("Invalid transaction!")
    
    def mine_pending_transactions(self, miner_address):
        reward_tx = Transaction("MINING_REWARD", miner_address, self.mining_reward)
        self.pending_transactions.append(reward_tx)

        new_block = Block(len(self.chain), [tx.__dict__ for tx in self.pending_transactions], self.chain[-1].hash)
        new_block.hash = self.proof_of_work(new_block)
        self.chain.append(new_block)

        self.pending_transactions = []

    def get_balance(self, public_key):
        balance = 0
        for block in self.chain:
            for tx in block.transactions:
                if tx["sender"] == public_key:
                    balance -= tx["amount"]
                if tx["recipient"] == public_key:
                    balance += tx["amount"]
        return balance

class Transaction:
    def __init__(self, sender, recipient, amount, signature=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature

    def compute_hash(self):
        tx_dict = {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount
        }
        tx_string = json.dumps(tx_dict, sort_keys=True)
        return hashlib.sha256(tx_string.encode()).digest()
    
    def sign_transaction(self, private_key):
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
        signature_bytes = sk.sign(self.compute_hash())
        self.signature = signature_bytes.hex()
    
    def is_valid(self):
        if self.sender == "MINING_REWARD":
            return True
        if not self.signature:
            return False
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(self.sender), curve=ecdsa.SECP256k1)
        try:
            return vk.verify(
                bytes.fromhex(self.signature),
                self.compute_hash()
            )
        except ecdsa.BadSignatureError:
            return False
        
if __name__ == "__main__":
    priv1, pub1 = generate_keys()
    priv2, pub2 = generate_keys()
    print("Wallet 1: ", pub1)
    print("Wallet 2: ", pub2)

    bc = Blockchain()

    tx1 = Transaction(pub1, pub2, 20)
    tx1.sign_transaction(priv1)
    bc.add_transaction(tx1)

    bc.mine_pending_transactions(pub1)

    print("Wallet 1 balance: ", bc.get_balance(pub1))
    print("Wallet 2 balance: ", bc.get_balance(pub2))