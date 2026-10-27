import math
from collections import Counter

def calculate_shannon_entropy(data: str) -> float:
    """
    Menghitung nilai Shannon Entropy H(X) dari string input.
    H(X) = -sum(P(x) * log2(P(x)))
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 2)

def is_high_entropy(data: str, threshold: float = 4.2) -> bool:
    """
    Mengecek apakah string memiliki nilai entropi di atas ambang batas (default: 4.2).
    """
    if len(data) < 16:  # Abaikan string terlalu pendek untuk menghindari false positive
        return False
    return calculate_shannon_entropy(data) >= threshold
