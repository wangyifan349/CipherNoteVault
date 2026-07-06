"""
Minimal BIP84 wallet script.

This script:
- runs exact self-tests
- creates 1000 secure random native SegWit wallets
- imports one private key from strict hex, decimal, compressed WIF, or uncompressed WIF
- prints results only and does not write any local file

Dependencies:
pip install ecdsa base58 bech32
"""

import re
import hashlib
import secrets
import base58
from ecdsa import SigningKey, SECP256k1
from bech32 import bech32_encode, convertbits

secp256k1_curve_order = SECP256k1.order  # secp256k1 curve order
batch_wallet_count = 1000  # Number of wallets created in batch mode
hex_private_key_pattern = re.compile(r"^[0-9a-fA-F]{64}$")  # Strict 32-byte private key hex pattern

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()  # Return SHA256 digest

def hash160(data: bytes) -> bytes:
    ripemd160_hasher = hashlib.new("ripemd160")  # Create RIPEMD160 hasher
    ripemd160_hasher.update(sha256(data))  # Hash SHA256 result with RIPEMD160
    return ripemd160_hasher.digest()  # Return HASH160 digest

def validate_private_key_range(private_key_int: int) -> None:
    is_valid_private_key = 1 <= private_key_int < secp256k1_curve_order  # Check secp256k1 private key range
    if not is_valid_private_key:
        raise ValueError("Private key must be in range [1, curve_order - 1].")  # Reject invalid private key

def private_key_to_compressed_public_key(private_key_int: int) -> bytes:
    validate_private_key_range(private_key_int)  # Validate private key before public key generation
    signing_key = SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)  # Create signing key from private key integer
    public_point = signing_key.verifying_key.pubkey.point  # Get elliptic curve public point
    public_key_x = public_point.x()  # Get public key x coordinate
    public_key_y = public_point.y()  # Get public key y coordinate
    is_even_public_key_y = public_key_y % 2 == 0  # Check y coordinate parity
    public_key_prefix = b"\x03"  # Default compressed public key prefix for odd y
    if is_even_public_key_y:
        public_key_prefix = b"\x02"  # Compressed public key prefix for even y
    return public_key_prefix + public_key_x.to_bytes(32, "big")  # Return compressed public key

def private_key_to_wif(private_key_int: int, is_testnet: bool = False, is_compressed_wif: bool = True) -> str:
    validate_private_key_range(private_key_int)  # Validate private key before WIF encoding
    network_prefix = b"\x80"  # Mainnet WIF prefix
    if is_testnet:
        network_prefix = b"\xef"  # Testnet WIF prefix
    private_key_bytes = private_key_int.to_bytes(32, "big")  # Convert private key integer to 32 bytes
    wif_payload = network_prefix + private_key_bytes  # Build WIF payload
    if is_compressed_wif:
        wif_payload += b"\x01"  # Add compressed WIF marker
    checksum = sha256(sha256(wif_payload))[:4]  # Build Base58Check checksum
    return base58.b58encode(wif_payload + checksum).decode()  # Return Base58Check WIF

def wif_to_private_key(wif_text: str) -> tuple[int, bool, bool, str]:
    cleaned_wif_text = wif_text.strip()  # Clean WIF input
    try:
        raw_wif_data = base58.b58decode(cleaned_wif_text)  # Decode Base58 WIF
    except Exception as error:
        raise ValueError("Invalid WIF Base58 encoding.") from error  # Reject non-Base58 WIF
    is_valid_wif_size = len(raw_wif_data) == 37 or len(raw_wif_data) == 38  # Check Base58Check WIF size
    if not is_valid_wif_size:
        raise ValueError("Invalid WIF length.")  # Reject invalid WIF length
    wif_payload = raw_wif_data[:-4]  # Split WIF payload
    wif_checksum = raw_wif_data[-4:]  # Split WIF checksum
    expected_checksum = sha256(sha256(wif_payload))[:4]  # Recalculate Base58Check checksum
    if wif_checksum != expected_checksum:
        raise ValueError("Invalid WIF checksum.")  # Reject invalid checksum
    network_prefix = wif_payload[0]  # Read WIF network prefix
    if network_prefix == 0x80:
        is_testnet = False  # Mainnet WIF
    elif network_prefix == 0xef:
        is_testnet = True  # Testnet WIF
    else:
        raise ValueError("Invalid WIF network prefix.")  # Reject unknown network prefix
    is_uncompressed_wif = len(wif_payload) == 33  # Uncompressed WIF has prefix + 32-byte private key
    is_compressed_wif = len(wif_payload) == 34 and wif_payload[-1] == 0x01  # Compressed WIF has final 0x01 marker
    if is_uncompressed_wif:
        private_key_bytes = wif_payload[1:33]  # Extract private key from uncompressed WIF
        imported_wif_type = "uncompressed"  # Store imported WIF type
        imported_wif_is_compressed = False  # Store compression flag
    elif is_compressed_wif:
        private_key_bytes = wif_payload[1:33]  # Extract private key from compressed WIF
        imported_wif_type = "compressed"  # Store imported WIF type
        imported_wif_is_compressed = True  # Store compression flag
    else:
        raise ValueError("Invalid WIF compressed marker.")  # Reject malformed compressed marker
    private_key_int = int.from_bytes(private_key_bytes, "big")  # Convert private key bytes to integer
    validate_private_key_range(private_key_int)  # Validate imported private key range
    return private_key_int, is_testnet, imported_wif_is_compressed, imported_wif_type  # Return parsed WIF data

def strict_hex_to_private_key(hex_text: str) -> int:
    cleaned_hex_text = hex_text.strip()  # Clean hex input
    has_hex_prefix = cleaned_hex_text.startswith("0x") or cleaned_hex_text.startswith("0X")  # Check optional 0x prefix
    if has_hex_prefix:
        cleaned_hex_text = cleaned_hex_text[2:]  # Remove 0x prefix
    if not hex_private_key_pattern.fullmatch(cleaned_hex_text):
        raise ValueError("Hex private key must be exactly 64 hexadecimal characters.")  # Reject non-strict private key hex
    private_key_int = int(cleaned_hex_text, 16)  # Convert strict hex private key to integer
    validate_private_key_range(private_key_int)  # Validate private key range
    return private_key_int  # Return private key integer

def decimal_text_to_private_key(decimal_text: str) -> int:
    cleaned_decimal_text = decimal_text.strip()  # Clean decimal input
    if not cleaned_decimal_text.isdecimal():
        raise ValueError("Decimal private key must contain digits only.")  # Reject non-decimal input
    private_key_int = int(cleaned_decimal_text, 10)  # Convert decimal private key to integer
    validate_private_key_range(private_key_int)  # Validate private key range
    return private_key_int  # Return private key integer

def public_key_to_bip84_address(compressed_public_key: bytes, is_testnet: bool = False) -> str:
    public_key_hash = hash160(compressed_public_key)  # Build HASH160 of compressed public key
    human_readable_part = "bc"  # Mainnet Bech32 human-readable part
    if is_testnet:
        human_readable_part = "tb"  # Testnet Bech32 human-readable part
    converted_public_key_hash = convertbits(public_key_hash, 8, 5, True)  # Convert 8-bit bytes to 5-bit Bech32 groups
    witness_program = [0]  # Native SegWit witness version 0
    for converted_value in converted_public_key_hash:
        witness_program.append(converted_value)  # Append converted public key hash value
    return bech32_encode(human_readable_part, witness_program)  # Return BIP84 P2WPKH address

def private_key_to_wallet(private_key_int: int, is_testnet: bool = False, imported_wif_is_compressed: bool | None = None) -> dict:
    compressed_public_key = private_key_to_compressed_public_key(private_key_int)  # Generate compressed public key
    wallet_data = {}  # Create wallet result dictionary
    wallet_data["network"] = "mainnet"  # Default network label
    if is_testnet:
        wallet_data["network"] = "testnet"  # Testnet network label
    wallet_data["private_key_hex"] = private_key_int.to_bytes(32, "big").hex()  # Store private key hex
    wallet_data["compressed_wif"] = private_key_to_wif(private_key_int, is_testnet, True)  # Store compressed WIF
    wallet_data["uncompressed_wif"] = private_key_to_wif(private_key_int, is_testnet, False)  # Store uncompressed WIF
    wallet_data["imported_wif_type"] = "none"  # Default imported WIF type
    if imported_wif_is_compressed is True:
        wallet_data["imported_wif_type"] = "compressed"  # Store imported compressed WIF type
    if imported_wif_is_compressed is False:
        wallet_data["imported_wif_type"] = "uncompressed"  # Store imported uncompressed WIF type
    wallet_data["compressed_public_key"] = compressed_public_key.hex()  # Store compressed public key
    wallet_data["hash160"] = hash160(compressed_public_key).hex()  # Store HASH160
    wallet_data["bip84_address"] = public_key_to_bip84_address(compressed_public_key, is_testnet)  # Store BIP84 address
    return wallet_data  # Return wallet result

def create_safe_random_private_key() -> int:
    private_key_int = secrets.randbelow(secp256k1_curve_order - 1) + 1  # Generate secure random private key without modulo bias
    return private_key_int  # Return private key integer

def import_private_key(private_key_text: str) -> tuple[int, bool, bool | None]:
    cleaned_private_key_text = private_key_text.strip()  # Clean user input
    has_hex_prefix = cleaned_private_key_text.startswith("0x") or cleaned_private_key_text.startswith("0X")  # Check explicit hex prefix
    if has_hex_prefix:
        private_key_int = strict_hex_to_private_key(cleaned_private_key_text)  # Import strict hex private key
        return private_key_int, False, None  # Hex import uses mainnet by default
    is_strict_hex_private_key = hex_private_key_pattern.fullmatch(cleaned_private_key_text) is not None  # Check exact 64-char hex
    if is_strict_hex_private_key:
        private_key_int = strict_hex_to_private_key(cleaned_private_key_text)  # Import strict hex private key
        return private_key_int, False, None  # Hex import uses mainnet by default
    if cleaned_private_key_text.isdecimal():
        private_key_int = decimal_text_to_private_key(cleaned_private_key_text)  # Import decimal private key
        return private_key_int, False, None  # Decimal import uses mainnet by default
    private_key_int, is_testnet, imported_wif_is_compressed, imported_wif_type = wif_to_private_key(cleaned_private_key_text)  # Import WIF by Base58Check
    return private_key_int, is_testnet, imported_wif_is_compressed  # Return imported private key data

def run_tests() -> None:
    test_vectors = (
        {
            "private_key_hex": "0000000000000000000000000000000000000000000000000000000000000001",
            "compressed_public_key": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "hash160": "751e76e8199196d454941c45d1b3a323f1433bd6",
            "compressed_wif": "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
            "uncompressed_wif": "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
            "bip84_address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        },
        {
            "private_key_hex": "0000000000000000000000000000000000000000000000000000000000000002",
            "compressed_public_key": "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "hash160": "06afd46bcdfd22ef94ac122aa11f241244a37ecc",
            "compressed_wif": "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4",
            "uncompressed_wif": "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAvUcVfH",
            "bip84_address": "bc1qq6hag67dl53wl99vzg42z8eyzfz2xlkvxechjp",
        },
        {
            "private_key_hex": "0000000000000000000000000000000000000000000000000000000000000003",
            "compressed_public_key": "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            "hash160": "7dd65592d0ab2fe0d0257d571abf032cd9db93dc",
            "compressed_wif": "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S",
            "uncompressed_wif": "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreB1FQ8BZ",
            "bip84_address": "bc1q0ht9tyks4vh7p5p904t340cr9nvahy7u3re7zg",
        },
    )  # Exact fixed test vectors
    for test_vector in test_vectors:
        private_key_int = int(test_vector["private_key_hex"], 16)  # Convert test private key hex to integer
        wallet_data = private_key_to_wallet(private_key_int, is_testnet=False)  # Generate wallet from test private key
        compressed_wif_data = wif_to_private_key(test_vector["compressed_wif"])  # Import compressed WIF test vector
        uncompressed_wif_data = wif_to_private_key(test_vector["uncompressed_wif"])  # Import uncompressed WIF test vector
        imported_compressed_key = compressed_wif_data[0]  # Read private key from compressed WIF
        compressed_wif_is_testnet = compressed_wif_data[1]  # Read network from compressed WIF
        compressed_wif_is_compressed = compressed_wif_data[2]  # Read compression flag from compressed WIF
        compressed_wif_type = compressed_wif_data[3]  # Read type label from compressed WIF
        imported_uncompressed_key = uncompressed_wif_data[0]  # Read private key from uncompressed WIF
        uncompressed_wif_is_testnet = uncompressed_wif_data[1]  # Read network from uncompressed WIF
        uncompressed_wif_is_compressed = uncompressed_wif_data[2]  # Read compression flag from uncompressed WIF
        uncompressed_wif_type = uncompressed_wif_data[3]  # Read type label from uncompressed WIF
        assert wallet_data["private_key_hex"] == test_vector["private_key_hex"], "Private key hex mismatch"
        assert wallet_data["compressed_public_key"] == test_vector["compressed_public_key"], "Compressed public key mismatch"
        assert wallet_data["hash160"] == test_vector["hash160"], "HASH160 mismatch"
        assert wallet_data["compressed_wif"] == test_vector["compressed_wif"], "Compressed WIF mismatch"
        assert wallet_data["uncompressed_wif"] == test_vector["uncompressed_wif"], "Uncompressed WIF mismatch"
        assert wallet_data["bip84_address"] == test_vector["bip84_address"], "BIP84 address mismatch"
        assert imported_compressed_key == private_key_int, "Compressed WIF private key mismatch"
        assert imported_uncompressed_key == private_key_int, "Uncompressed WIF private key mismatch"
        assert compressed_wif_is_testnet is False, "Compressed WIF network mismatch"
        assert uncompressed_wif_is_testnet is False, "Uncompressed WIF network mismatch"
        assert compressed_wif_is_compressed is True, "Compressed WIF type mismatch"
        assert uncompressed_wif_is_compressed is False, "Uncompressed WIF type mismatch"
        assert compressed_wif_type == "compressed", "Compressed WIF label mismatch"
        assert uncompressed_wif_type == "uncompressed", "Uncompressed WIF label mismatch"
    invalid_private_keys = (0, secp256k1_curve_order, secp256k1_curve_order + 1)  # Invalid private key samples
    for invalid_private_key in invalid_private_keys:
        try:
            private_key_to_wallet(invalid_private_key)  # Try invalid private key
            raise AssertionError("Invalid private key was accepted.")  # Fail if invalid key is accepted
        except ValueError:
            pass  # Expected rejection
    print("All exact tests passed.")  # Print test result

def create_batch_wallets() -> None:
    print("Creating wallets:", batch_wallet_count)  # Print batch count
    for wallet_index in range(1, batch_wallet_count + 1):
        private_key_int = create_safe_random_private_key()  # Generate secure random private key
        wallet_data = private_key_to_wallet(private_key_int, is_testnet=False)  # Generate mainnet wallet data
        print("\nindex:", wallet_index)  # Print wallet index
        print("private_key_wif:", wallet_data["compressed_wif"])  # Print compressed WIF private key
        print("private_key_decimal:", private_key_int)  # Print decimal private key
        print("compressed_public_key:", wallet_data["compressed_public_key"])  # Print compressed public key
        print("bip84_address:", wallet_data["bip84_address"])  # Print BIP84 address
    print("\nCreated wallets:", batch_wallet_count)  # Print batch completion message

def import_one_wallet() -> None:
    private_key_text = input("Input one strict 64-char private key hex, decimal, or WIF: ").strip()  # Read one private key
    imported_private_key_data = import_private_key(private_key_text)  # Parse imported private key
    private_key_int = imported_private_key_data[0]  # Read private key integer
    is_testnet = imported_private_key_data[1]  # Read imported network flag
    imported_wif_is_compressed = imported_private_key_data[2]  # Read imported WIF compression flag
    wallet_data = private_key_to_wallet(private_key_int, is_testnet, imported_wif_is_compressed)  # Generate wallet data
    print("private_key_wif:", wallet_data["compressed_wif"])  # Print compressed WIF private key
    print("private_key_decimal:", private_key_int)  # Print decimal private key
    print("compressed_public_key:", wallet_data["compressed_public_key"])  # Print compressed public key
    print("bip84_address:", wallet_data["bip84_address"])  # Print BIP84 address

def run_main_menu() -> None:
    while True:
        print("\n1. Create 1000 safe random BIP84 wallets")
        print("2. Import one private key")
        print("3. Exit")
        menu_choice = input("Choose: ").strip()  # Read menu choice
        if menu_choice == "1":
            create_batch_wallets()  # Create 1000 wallets and print them
            continue
        if menu_choice == "2":
            try:
                import_one_wallet()  # Import one private key and print wallet data
            except Exception as error:
                print("Import failed:", error)  # Print import error without stopping program
            continue
        if menu_choice == "3":
            break  # Exit program
        print("Invalid choice.")  # Reject unknown menu choice

if __name__ == "__main__":
    run_tests()  # Run exact self-tests first
    run_main_menu()  # Start interactive menu
