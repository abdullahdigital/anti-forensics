import os
import math

def calculate_entropy(data):
    """
    Calculate the Shannon entropy of a given byte string.
    High entropy often indicates encryption or compression.
    """
    if not data:
        return 0

    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def detect_encrypted_file(file_path, block_size=4096, entropy_threshold=7.0):
    """
    Detects if a file is likely encrypted by analyzing its entropy.
    
    Args:
        file_path (str): The path to the file to analyze.
        block_size (int): The size of the block to read for entropy calculation.
        entropy_threshold (float): The entropy value above which a file is considered
                                   potentially encrypted. (Max entropy for a byte is 8.0)
                                   
    Returns:
        dict: A dictionary containing the file path, calculated entropy, and a boolean
              indicating if it's likely encrypted.
    """
    if not os.path.exists(file_path):
        return {"error": "File not found", "file_path": file_path}

    try:
        with open(file_path, 'rb') as f:
            # Read a block of the file to calculate entropy
            # Reading the whole file might be too slow for large files
            data = f.read(block_size)
            if not data:
                return {"file_path": file_path, "entropy": 0.0, "is_encrypted": False, "note": "File is empty or too small for analysis"}

            entropy = calculate_entropy(data)
            is_encrypted = entropy > entropy_threshold
            
            return {
                "file_path": file_path,
                "entropy": round(entropy, 4),
                "entropy_threshold": entropy_threshold,
                "is_encrypted": is_encrypted,
                "note": "High entropy often indicates encryption or compression."
            }
    except Exception as e:
        return {"error": str(e), "file_path": file_path}

if __name__ == '__main__':
    # Example Usage
    # Create a dummy file with low entropy (e.g., text file)
    low_entropy_file = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\low_entropy.txt"
    with open(low_entropy_file, 'w') as f:
        f.write("This is a simple text file with low entropy. It should not be detected as encrypted.")
    
    print(f"Analyzing low entropy file: {low_entropy_file}")
    result_low = detect_encrypted_file(low_entropy_file)
    print(result_low)
    os.remove(low_entropy_file)

    # Create a dummy file with high entropy (simulating encrypted data)
    # For a real test, you'd encrypt a file or use random bytes
    high_entropy_file = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\high_entropy.bin"
    with open(high_entropy_file, 'wb') as f:
        f.write(os.urandom(4096)) # Write 4KB of random bytes
    
    print(f"Analyzing high entropy file: {high_entropy_file}")
    result_high = detect_encrypted_file(high_entropy_file)
    print(result_high)
    os.remove(high_entropy_file)

    # Test with an empty file
    empty_file = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\empty.txt"
    open(empty_file, 'a').close()
    print(f"Analyzing empty file: {empty_file}")
    result_empty = detect_encrypted_file(empty_file)
    print(result_empty)
    os.remove(empty_file)