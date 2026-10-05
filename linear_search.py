import time

class LinearSearchTable:
    """
    Baseline Linear Search array implementation.
    Iterates sequentially through the array to find matching IP records.
    Time Complexity: O(n) average and worst case.
    """
    def __init__(self):
        self.records = []  # List of tuples: (ip_str, record_dict)

    def insert(self, key: str, value: dict):
        """Appends record to the flat list or updates if key exists."""
        for idx, (existing_key, _) in enumerate(self.records):
            if existing_key == key:
                self.records[idx] = (key, value)
                return
        self.records.append((key, value))

    def search(self, key: str) -> tuple:
        """
        Searches sequentially for key in array.
        Returns tuple: (record_dict or None, comparisons_count, lookup_time_us)
        """
        start_time = time.perf_counter()
        comparisons = 0

        for existing_key, val in self.records:
            comparisons += 1
            if existing_key == key:
                end_time = time.perf_counter()
                time_us = (end_time - start_time) * 1e6
                return (val, comparisons, time_us)

        end_time = time.perf_counter()
        time_us = (end_time - start_time) * 1e6
        return (None, comparisons, time_us)

    def delete(self, key: str) -> bool:
        """Deletes key from array via linear search."""
        for idx, (existing_key, _) in enumerate(self.records):
            if existing_key == key:
                self.records.pop(idx)
                return True
        return False

    def size(self) -> int:
        return len(self.records)
