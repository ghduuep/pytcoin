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

def merkle_root(transactions):
    tx_hashes = [tx.compute_hash() for tx in transactions]

    if not tx_hashes:
        return None

    while len(tx_hashes) > 1:
        if len(tx_hashes) % 2 != 0:
            tx_hashes.append(tx_hashes[-1])

        new_level = []
        for i in range(0, len(tx_hashes), 2):
            combined = tx_hashes[i] + tx_hashes[i + 1]
            new_hash = hashlib.sha256(combined.encode()).hexdigest()
            new_level.append(new_level)
        
        tx_hashes = new_level

    return tx_hashes[0]

class Block:
    def __init__(self, index, transactions, previous_hash, nonce=0):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.merkle_root = merkle_root(transactions)
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
class Blockchain:

    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.create_genesis_block()
        self.utxos = {}
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
        while True:
            hash_attempt = block.compute_hash()
            if hash_attempt.startswith("0" * self.difficulty):
                return hash_attempt
            block.nonce += 1
    
    def is_valid_transaction(self, tx):
        if len(tx.inputs) == 0:
            return True

        input_total = 0
        output_total = 0

        for i, tx_input in enumerate(tx.inputs):
            key = (tx_input.tx_id, tx_input.output_index)

            if key not in self.utxos:
                return False
            
            referenced_output = self.utxos[key]

            if referenced_output.recipient != tx_input.public_key:
                return False
            
            try:
                vk = ecdsa.VerifyingKey.from_string(
                    bytes.fromhex(tx_input.public_key),
                    curve=ecdsa.SECP256k1
                )

                message = tx.compute_hash().encode()

                if not vk.verify(bytes.fromhex(tx_input.signature), message):
                    return False
            except:
                return False
            
            input_total += referenced_output.amount

        for output in tx.outputs:
            output_total += output.amount

            return input_total >= output_total
    
    def add_transaction(self, tx):
        if self.is_valid_transaction(tx):
            self.pending_transactions.append(tx)
        else:
            print("Invalid transaction!")
    
    def update_utxos(self, block):
        for tx in block.transactions:
            tx_id = tx.compute_hash()

            for tx_input in tx.inputs:
                key = (tx_input.tx_id, tx_input.output_index)
                if key in self.utxos:
                    del self.utxos[key]
            
            for index, output in enumerate(tx.outputs):
                self.utxos[(tx_id, index)] = output

    def mine(self, miner_address):
        def fee(tx):
            if len(tx.inputs) == 0:
                return 0
            inp = sum(self.utxos[(i.tx_id, i.output_index)].amount for i in tx.inputs)
            out = sum(o.amount for o in tx.outputs)
            return inp - out
        
        self.pending_transactions.sort(key=fee, reverse=True)

        total_fees = sum(fee(tx) for tx in self.pending_transactions)

        reward_tx = Transaction([], [TxOutput(miner_address, self.mining_reward + total_fees)])
        self.pending_transactions.append(reward_tx)

        block = Block(len(self.chain), self.pending_transactions, self.chain[-1].hash)
        block.hash = self.proof_of_work(block)

        if self.is_valid_block(block):
            self.chain.append(block)
            self.update_utxos(block)
            self.pending_transactions = []

    def is_valid_block(self, block):
        if block.previous_hash != self.chain[-1].hash:
            return False
        
        if not block.hash.startswith("0" * self.difficulty):
            return False
        
        if block.merkle_root != merkle_root(block.transactions):
            return False
        
        for tx in block.transactions:
            if not self.is_valid_transaction(tx):
                return False
        
        return True

    def get_balance(self, address):
        balance = 0
        for (_, _), output in self.utxos.items():
            if output.recipient == address:
                balance += output.amount
        return balance

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

