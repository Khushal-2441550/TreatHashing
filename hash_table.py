import time
from hash_function import custom_hash, validate_ipv4

class HashNode:
    """Linked list node for Separate Chaining collision handling."""
    def __init__(self, key: str, value: dict):
        self.key = key          # IP address
        self.value = value      # Threat record dictionary
        self.next = None        # Pointer to next node in chain

class HashTable:
    """
    Custom Hash Table implementation with Separate Chaining for collision resolution.
    Explicitly built for DAA analysis (without using Python dict built-in).
    """
    def __init__(self, capacity: int = 10007):
        self.capacity = capacity
        self.buckets = [None] * capacity
        self.size = 0
        self.total_collisions = 0

    def _hash(self, key: str) -> int:
        return custom_hash(key, self.capacity)

    def insert(self, key: str, value: dict) -> bool:
        """
        Inserts or updates a key-value record in the Hash Table.
        Returns True if inserted/updated successfully.
        """
        if not validate_ipv4(key):
            return False

        index = self._hash(key)
        head = self.buckets[index]

        # Case 1: Empty bucket slot
        if head is None:
            self.buckets[index] = HashNode(key, value)
            self.size += 1
            return True

        # Case 2: Bucket slot already occupied -> Collision occurs!
        current = head
        prev = None
        chain_length = 0

        while current is not None:
            chain_length += 1
            # If key already exists, update record
            if current.key == key:
                current.value = value
                return True
            prev = current
            current = current.next

        # New key collided with existing elements in bucket
        self.total_collisions += 1
        prev.next = HashNode(key, value)
        self.size += 1
        return True

    def search(self, key: str) -> tuple:
        """
        Searches for an IP key in the Hash Table.
        Returns tuple: (record_dict or None, comparisons_count, hash_index, chain_depth, lookup_time_us)
        """
        start_time = time.perf_counter()
        if not validate_ipv4(key):
            end_time = time.perf_counter()
            return (None, 0, -1, -1, (end_time - start_time) * 1e6)

        index = self._hash(key)
        current = self.buckets[index]
        comparisons = 0
        depth = 0

        while current is not None:
            comparisons += 1
            if current.key == key:
                end_time = time.perf_counter()
                time_us = (end_time - start_time) * 1e6
                return (current.value, comparisons, index, depth, time_us)
            current = current.next
            depth += 1

        end_time = time.perf_counter()
        time_us = (end_time - start_time) * 1e6
        return (None, comparisons, index, -1, time_us)

    def delete(self, key: str) -> bool:
        """
        Deletes an IP key from the Hash Table.
        Returns True if deleted, False if not found.
        """
        if not validate_ipv4(key):
            return False

        index = self._hash(key)
        current = self.buckets[index]
        prev = None

        while current is not None:
            if current.key == key:
                if prev is None:
                    # Deleting head node of chain
                    self.buckets[index] = current.next
                else:
                    prev.next = current.next
                self.size -= 1
                return True
            prev = current
            current = current.next

        return False

    def get_stats(self) -> dict:
        """Calculates hash table metrics: load factor, max chain, avg chain, collisions."""
        chain_lengths = []
        occupied_buckets = 0

        for head in self.buckets:
            if head is not None:
                occupied_buckets += 1
                length = 0
                curr = head
                while curr:
                    length += 1
                    curr = curr.next
                chain_lengths.append(length)

        max_chain = max(chain_lengths) if chain_lengths else 0
        avg_chain = (sum(chain_lengths) / occupied_buckets) if occupied_buckets > 0 else 0
        load_factor = self.size / self.capacity

        return {
            "total_records": self.size,
            "capacity": self.capacity,
            "occupied_buckets": occupied_buckets,
            "empty_buckets": self.capacity - occupied_buckets,
            "load_factor": round(load_factor, 4),
            "total_collisions": self.total_collisions,
            "max_chain_length": max_chain,
            "avg_chain_length": round(avg_chain, 2)
        }

    def get_bucket_chain(self, index: int) -> list:
        """Returns all IP keys in a specific bucket index."""
        if index < 0 or index >= self.capacity:
            return []
        chain = []
        curr = self.buckets[index]
        while curr:
            chain.append(curr.key)
            curr = curr.next
        return chain

    def get_collision_sample(self, limit: int = 10) -> list:
        """Returns sample buckets that have collision chains (length > 1)."""
        samples = []
        for idx, head in enumerate(self.buckets):
            if head and head.next:
                chain = self.get_bucket_chain(idx)
                samples.append({
                    "bucket_index": idx,
                    "chain_length": len(chain),
                    "ips": chain
                })
                if len(samples) >= limit:
                    break
        return samples

if __name__ == "__main__":
    ht = HashTable(capacity=100)
    ht.insert("185.220.101.25", {"threat_type": "Botnet", "severity": "High"})
    ht.insert("45.33.32.156", {"threat_type": "Scanner", "severity": "Medium"})
    
    rec, comp, idx, depth, t_us = ht.search("185.220.101.25")
    print(f"Search result: {rec}, Comparisons: {comp}, Index: {idx}, Time: {t_us:.2f}us")
    print("Stats:", ht.get_stats())
