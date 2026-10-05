import re

def validate_ipv4(ip_str: str) -> bool:
    """
    Validates whether an input string is a valid IPv4 address.
    Format: A.B.C.D where 0 <= A,B,C,D <= 255
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    parts = ip_str.strip().split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        val = int(part)
        if val < 0 or val > 255:
            return False
        # Disallow leading zeros like 01.02.03.04 unless it's just '0'
        if len(part) > 1 and part.startswith("0"):
            return False
    return True

def ip_to_int(ip_str: str) -> int:
    """
    Converts IPv4 string into a 32-bit unsigned integer.
    Formula: (Octet1 * 256^3) + (Octet2 * 256^2) + (Octet3 * 256) + Octet4
    """
    octets = [int(x) for x in ip_str.strip().split(".")]
    return (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]

def custom_hash(ip_str: str, capacity: int) -> int:
    """
    Custom Hash Function for IPv4 addresses.
    Uses Knuth's Multiplicative Hashing formula:
    hash_val = (ip_int * 2654435761) % (2^32)
    bucket_index = hash_val % capacity
    
    2654435761 is golden ratio prime multiplier (2^32 * (sqrt(5)-1)/2)
    """
    ip_int = ip_to_int(ip_str)
    GOLDEN_RATIO_PRIME = 2654435761
    hash_32bit = (ip_int * GOLDEN_RATIO_PRIME) & 0xFFFFFFFF
    bucket_index = hash_32bit % capacity
    return bucket_index

def explain_hash(ip_str: str, capacity: int) -> dict:
    """
    Provides step-by-step mathematical breakdown of the custom hash function
    for DAA educational demonstration.
    """
    if not validate_ipv4(ip_str):
        return {"valid": False, "error": "Invalid IPv4 Address Format"}
    
    octets = [int(x) for x in ip_str.strip().split(".")]
    octet_calc_str = f"({octets[0]} × 256³) + ({octets[1]} × 256²) + ({octets[2]} × 256) + {octets[3]}"
    ip_int = ip_to_int(ip_str)
    
    GOLDEN_RATIO_PRIME = 2654435761
    hash_32bit = (ip_int * GOLDEN_RATIO_PRIME) & 0xFFFFFFFF
    bucket_index = hash_32bit % capacity
    
    return {
        "valid": True,
        "ip": ip_str,
        "octets": octets,
        "octet_calc_str": octet_calc_str,
        "ip_int": ip_int,
        "ip_int_hex": f"0x{ip_int:08X}",
        "multiplier": GOLDEN_RATIO_PRIME,
        "hash_32bit": hash_32bit,
        "hash_32bit_hex": f"0x{hash_32bit:08X}",
        "capacity": capacity,
        "bucket_index": bucket_index,
        "formula": f"Index = ({ip_int} × 2654435761 mod 2³²) mod {capacity} = {bucket_index}"
    }

if __name__ == "__main__":
    test_ip = "185.220.101.25"
    print(f"Validation of {test_ip}: {validate_ipv4(test_ip)}")
    print(f"IP to Integer: {ip_to_int(test_ip)}")
    print(f"Custom Hash (cap 10007): {custom_hash(test_ip, 10007)}")
    print("Breakdown:", explain_hash(test_ip, 10007))
