import os
import csv
from hash_function import validate_ipv4, ip_to_int, custom_hash, explain_hash
from hash_table import HashTable
from linear_search import LinearSearchTable
from data_generator import generate_dataset

def test_all():
    print("--- 1. Testing Hash Function & Validation ---")
    assert validate_ipv4("185.220.101.25") == True
    assert validate_ipv4("256.0.0.1") == False
    assert validate_ipv4("invalid.ip") == False
    print("[OK] IPv4 validation passed.")
    
    assert ip_to_int("0.0.0.1") == 1
    assert ip_to_int("1.0.0.0") == 16777216
    print("[OK] IP to int conversion passed.")
    
    explanation = explain_hash("185.220.101.25", 10007)
    assert explanation["valid"] == True
    print(f"[OK] Hash explanation formula: {explanation['formula']}")
    
    print("\n--- 2. Testing Hash Table CRUD & Collision Handling ---")
    ht = HashTable(capacity=100)
    rec1 = {"threat_type": "Botnet", "severity": "High"}
    rec2 = {"threat_type": "Phishing", "severity": "Medium"}
    
    # Test Insert
    assert ht.insert("185.220.101.25", rec1) == True
    assert ht.insert("45.33.32.156", rec2) == True
    assert ht.size == 2
    
    # Test Search
    val, comp, idx, depth, t_us = ht.search("185.220.101.25")
    assert val == rec1
    assert comp >= 1
    print(f"[OK] Search key 185.220.101.25 found in bucket {idx}, depth {depth}, time {t_us:.2f}us.")
    
    # Test Update
    rec1_updated = {"threat_type": "Botnet", "severity": "Critical"}
    ht.insert("185.220.101.25", rec1_updated)
    val_up, _, _, _, _ = ht.search("185.220.101.25")
    assert val_up["severity"] == "Critical"
    assert ht.size == 2
    print("[OK] Update existing key passed.")
    
    # Test Delete
    assert ht.delete("185.220.101.25") == True
    assert ht.size == 1
    val_del, _, _, _, _ = ht.search("185.220.101.25")
    assert val_del is None
    print("[OK] Deletion passed.")
    
    print("\n--- 3. Testing Linear Search Table ---")
    lst = LinearSearchTable()
    lst.insert("185.220.101.25", rec1)
    lst.insert("45.33.32.156", rec2)
    res, comp_lst, t_lst = lst.search("45.33.32.156")
    assert res == rec2
    assert comp_lst == 2
    print(f"[OK] Linear search found element with {comp_lst} comparisons.")
    
    print("\n--- 4. All algorithmic tests passed successfully! ---")

if __name__ == "__main__":
    test_all()
