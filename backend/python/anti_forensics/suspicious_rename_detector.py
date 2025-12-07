
import os
import platform
import re
from datetime import datetime

# Placeholder for AI model for suspicious rename detection
def load_rename_detection_ai_model():
    """
    Loads a pre-trained AI model for suspicious rename detection.
    This is a placeholder function. In a real-world scenario, this would load
    a model (e.g., a classification model trained on rename patterns).
    """
    print("Loading AI model for suspicious rename detection...")
    # Example: model = tf.keras.models.load_model('rename_model.h5')
    # For now, it returns a dummy object.
    class DummyModel:
        def predict(self, data):
            # Simulate a prediction: 0 for benign, 1 for suspicious
            # In a real model, 'data' would be features extracted from rename events
            return 0.1 if "suspicious" in data.lower() else 0.9 # Higher score for suspicious
    return DummyModel()

rename_ai_model = load_rename_detection_ai_model()

def is_system_file(file_path):
    """
    Checks if a given file path points to a common system file or directory.
    This is a heuristic and can be expanded.
    """
    system_paths = [
        "C:\\Windows", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
        "/etc", "/dev", "/proc", "/sys", "/lib", "/lib64",
        "Program Files", "Program Files (x86)", "Windows\\System32"
    ]
    file_path_lower = file_path.lower()
    for sp in system_paths:
        if sp.lower() in file_path_lower:
            return True
    return False

def detect_suspicious_extension_change(old_name, new_name):
    """
    Detects suspicious changes in file extensions, e.g., .txt to .exe.
    """
    old_ext = os.path.splitext(old_name)[1].lower()
    new_ext = os.path.splitext(new_name)[1].lower()

    if old_ext and new_ext and old_ext != new_ext:
        # Common executable or script extensions
        suspicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.sh', '.py']
        if old_ext not in suspicious_extensions and new_ext in suspicious_extensions:
            return True, f"Changed from {old_ext} to suspicious executable extension {new_ext}"
        if new_ext == '.lnk' and old_ext != '.lnk':
            return True, f"Changed to .lnk (shortcut) from {old_ext}"
        if new_ext == '' and old_ext != '': # Extension removed
            return True, f"Extension removed from {old_ext}"
    return False, "No suspicious extension change"

def detect_hidden_file_rename(old_name, new_name):
    """
    Detects if a file is renamed to become a hidden file (e.g., adding a dot prefix on Unix-like systems).
    """
    old_basename = os.path.basename(old_name)
    new_basename = os.path.basename(new_name)

    if platform.system() != "Windows": # Unix-like systems
        if not old_basename.startswith('.') and new_basename.startswith('.'):
            return True, "File renamed to a hidden file (dot prefix added)"
    # On Windows, hidden attribute is set via file system API, not just name.
    # This would require integration with pywin32 or similar.
    return False, "No suspicious hidden file rename detected"

def detect_suspicious_character_rename(old_name, new_name):
    """
    Detects suspicious characters or patterns in new file names, often used for obfuscation.
    """
    # Look for multiple dots, unusual Unicode characters, or control characters
    if ".." in new_name or new_name.count('.') > 2:
        return True, "New name contains multiple dots or unusual dot patterns"
    if re.search(r'[^ -~]', new_name): # Non-ASCII printable characters
        return True, "New name contains non-ASCII printable characters"
    return False, "No suspicious character patterns"

def detect_suspicious_rename_ai(old_file_path, new_file_path):
    """
    Placeholder for AI-based suspicious rename detection.
    In a real implementation, features like file type, user, process, rename frequency,
    and content similarity would be fed to the AI model.
    """
    global rename_ai_model
    if rename_ai_model is None:
        rename_ai_model = load_rename_detection_ai_model()

    # Simulate feature extraction for the AI model
    # This is highly simplified. Real features would be numerical/categorical.
    features = f"rename event from {old_file_path} to {new_file_path}"
    
    # The AI model would return a probability or a class label
    prediction_score = rename_ai_model.predict(features)

    is_ai_suspicious = prediction_score > 0.5 # Threshold for suspicion

    ai_details = {
        "model_prediction_score": prediction_score,
        "is_ai_suspicious": is_ai_suspicious,
        "note": "AI model requires training on a dataset of benign and malicious rename events. Features would include file type, parent process, user, entropy of name change, etc."
    }
    return ai_details

def detect_suspicious_rename(old_file_path, new_file_path):
    """
    Detects suspicious file renames by combining heuristic checks and AI-based analysis.

    Args:
        old_file_path (str): The original path of the file.
        new_file_path (str): The new path of the file after renaming.

    Returns:
        dict: A dictionary containing the suspicious rename detection results.
    """
    results = {
        "old_file_path": old_file_path,
        "new_file_path": new_file_path,
        "timestamp": datetime.now().isoformat()
    }

    is_suspicious = False
    suspicion_reasons = []

    # Heuristic Check 1: Rename of a known system file/path
    if is_system_file(old_file_path) or is_system_file(new_file_path):
        is_suspicious = True
        suspicion_reasons.append("Rename involves a known system file or path.")

    # Heuristic Check 2: Suspicious extension change
    ext_change_suspicious, ext_change_reason = detect_suspicious_extension_change(old_file_path, new_file_path)
    if ext_change_suspicious:
        is_suspicious = True
        suspicion_reasons.append(ext_change_reason)

    # Heuristic Check 3: Rename to hidden file
    hidden_rename_suspicious, hidden_rename_reason = detect_hidden_file_rename(old_file_path, new_file_path)
    if hidden_rename_suspicious:
        is_suspicious = True
        suspicion_reasons.append(hidden_rename_reason)

    # Heuristic Check 4: Suspicious characters in new name
    char_rename_suspicious, char_rename_reason = detect_suspicious_character_rename(old_file_path, new_file_path)
    if char_rename_suspicious:
        is_suspicious = True
        suspicion_reasons.append(char_rename_reason)

    # AI-based detection
    ai_rename_result = detect_suspicious_rename_ai(old_file_path, new_file_path)
    results["ai_detection"] = ai_rename_result
    if ai_rename_result["is_ai_suspicious"]:
        is_suspicious = True
        suspicion_reasons.append("AI model flagged rename as suspicious.")

    results["is_suspicious_rename"] = is_suspicious
    results["suspicion_reasons"] = suspicion_reasons

    if not is_suspicious:
        results["note"] = "No suspicious rename patterns detected by heuristics or AI."

    return results

if __name__ == "__main__":
    print("Running suspicious rename detector tests...")

    # Test cases
    # 1. Benign rename
    result1 = detect_suspicious_rename("document.txt", "report.txt")
    print(f"\nTest Case 1 (Benign): {result1}")

    # 2. Suspicious extension change (txt to exe)
    result2 = detect_suspicious_rename("image.jpg", "malware.exe")
    print(f"\nTest Case 2 (Suspicious Extension): {result2}")

    # 3. Rename to hidden file (Unix-like)
    if platform.system() != "Windows":
        result3 = detect_suspicious_rename("/home/user/file.txt", "/home/user/.hidden_file")
        print(f"\nTest Case 3 (Hidden File Rename): {result3}")
    else:
        print("\nTest Case 3 (Hidden File Rename): Skipped on Windows.")

    # 4. Rename involving system path
    result4 = detect_suspicious_rename("C:\\Users\\user\\temp.txt", "C:\\Windows\\System32\\drivers\\temp.dll")
    print(f"\nTest Case 4 (System Path Involvement): {result4}")

    # 5. Suspicious characters
    result5 = detect_suspicious_rename("normal.doc", "invoice..pdf")
    print(f"\nTest Case 5 (Suspicious Characters): {result5}")

    result6 = detect_suspicious_rename("report.pdf", "report\u200e.pdf") # Unicode control character
    print(f"\nTest Case 6 (Unicode Control Character): {result6}")

    # 6. AI-flagged (simulated)
    # To simulate AI flagging, we'd need to modify the dummy model or input
    # For now, the dummy model gives a low suspicion score unless "suspicious" is in the input.
    result7 = detect_suspicious_rename("legit.txt", "suspicious_activity.log")
    print(f"\nTest Case 7 (AI Flagged - simulated): {result7}")
