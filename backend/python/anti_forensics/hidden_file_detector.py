import os
import platform

try:
    import win32api
    import win32con
except ImportError:
    win32api = None
    win32con = None
    print("pywin32 modules not found. Windows hidden/system attribute detection will be skipped.")

def find_hidden_items_heuristic(path):
    """
    Finds potentially hidden files and directories within a given path using heuristic rules.

    Args:
        path (str): The directory path to search.

    Returns:
        list: A list of dictionaries, each describing a detected hidden item.
    """
    hidden_items = []

    if not os.path.isdir(path):
        return []

    for root, dirs, files in os.walk(path):
        for name in dirs:
            full_path = os.path.join(root, name)
            # Unix-like hidden directories
            if name.startswith('.'):
                hidden_items.append({"type": "directory", "name": name, "path": full_path, "reason": "Starts with '.'"})
            # Windows hidden/system attributes
            if platform.system() == "Windows" and win32api:
                attrs = check_windows_attributes(full_path)
                if attrs.get("is_hidden"):
                    hidden_items.append({"type": "directory", "name": name, "path": full_path, "reason": "Windows Hidden Attribute"})
                if attrs.get("is_system"):
                    hidden_items.append({"type": "directory", "name": name, "path": full_path, "reason": "Windows System Attribute"})

        for name in files:
            full_path = os.path.join(root, name)
            # Unix-like hidden files
            if name.startswith('.'):
                hidden_items.append({"type": "file", "name": name, "path": full_path, "reason": "Starts with '.'"})
            
            # Files with no extension (can be suspicious)
            if '.' not in name and name != "":
                hidden_items.append({"type": "file", "name": name, "path": full_path, "reason": "No file extension"})

            # Windows hidden/system attributes
            if platform.system() == "Windows" and win32api:
                attrs = check_windows_attributes(full_path)
                if attrs.get("is_hidden"):
                    hidden_items.append({"type": "file", "name": name, "path": full_path, "reason": "Windows Hidden Attribute"})
                if attrs.get("is_system"):
                    hidden_items.append({"type": "file", "name": name, "path": full_path, "reason": "Windows System Attribute"})

    return hidden_items

    return hidden_items

def check_windows_attributes(file_path):
    """
    Checks if a file or directory has hidden or system attributes on Windows.
    Requires pywin32 library.

    Args:
        file_path (str): The path to the file or directory.

    Returns:
        dict: A dictionary indicating if hidden/system attributes are set.
    """
    if not win32api:
        return {"is_hidden": False, "is_system": False, "note": "pywin32 not installed."}

    try:
        attributes = win32api.GetFileAttributes(file_path)
        is_hidden = bool(attributes & win32con.FILE_ATTRIBUTE_HIDDEN)
        is_system = bool(attributes & win32con.FILE_ATTRIBUTE_SYSTEM)
        return {"is_hidden": is_hidden, "is_system": is_system}
    except Exception as e:
        return {"is_hidden": False, "is_system": False, "error": str(e)}

def detect_hidden_files_ai(file_path):
    """
    Placeholder for AI-based hidden file/partition detection.

    AI-based detection could involve more sophisticated analysis beyond simple naming conventions
    or file attributes. This might include:

    Model Training Requirements:
    1.  **Dataset:** A dataset of file system structures, disk images, or file metadata
        where hidden files/partitions have been deliberately created using various techniques
        (e.g., alternate data streams, embedded in legitimate files, disguised file types,
        unallocated space manipulation). Labeled examples of both hidden and legitimate files
        are crucial.
    2.  **Feature Extraction:** Features could include file system metadata anomalies,
        statistical properties of file content (e.g., entropy for disguised executables),
        discrepancies in file size vs. reported size, or patterns in disk allocation tables.
    3.  **Model Architecture:** Machine learning models (e.g., SVM, Random Forest) or deep
        learning models (e.g., CNNs for raw disk image analysis, LSTMs for file system journal
        analysis) could be used.
    4.  **Computational Resources:** Training and inference for these models may require
        significant computational resources.

    Args:
        file_path (str): The path to the file or directory to analyze.

    Returns:
        dict: A dictionary indicating the AI detection status and notes on requirements.
    """
    if not os.path.exists(file_path):
        return {"error": "File not found", "file_path": file_path}

    return {
        "file_path": file_path,
        "is_ai_hidden_suspected": False, # Placeholder result
        "confidence": 0.0, # Placeholder confidence
        "note": "AI-based hidden file detection is a placeholder. Requires a trained machine learning model. See function docstring for model training requirements."
    }

def detect_hidden_files(path):
    """
    Detects potentially hidden files and directories by combining heuristic
    checks and a placeholder for AI-based analysis.

    Args:
        path (str): The directory path to search.

    Returns:
        dict: A dictionary containing the hidden file detection results.
    """
    results = {"path": path}

    heuristic_hidden_items = find_hidden_items_heuristic(path)
    results["heuristic_detection"] = {
        "hidden_items": heuristic_hidden_items,
        "is_hidden_suspected": bool(heuristic_hidden_items)
    }

    ai_detection_result = detect_hidden_files_ai(path)
    results["ai_detection"] = ai_detection_result

    is_overall_hidden_suspected = (
        results["heuristic_detection"]["is_hidden_suspected"] or
        ai_detection_result.get("is_ai_hidden_suspected", False)
    )

    results["is_hidden_files_suspected"] = is_overall_hidden_suspected

    return results

if __name__ == '__main__':
    # Example Usage
    test_dir = "d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\test_hidden_files"
    os.makedirs(test_dir, exist_ok=True)

    # Create some dummy hidden files/dirs
    with open(os.path.join(test_dir, ".hidden_file.txt"), 'w') as f: f.write("hidden content")
    os.makedirs(os.path.join(test_dir, ".hidden_dir"), exist_ok=True)
    with open(os.path.join(test_dir, "no_extension_file"), 'w') as f: f.write("content")
    with open(os.path.join(test_dir, "normal_file.txt"), 'w') as f: f.write("normal content")

    print(f"Searching for hidden files in: {test_dir}")
    results = detect_hidden_files(test_dir)
    print(results)

    # Clean up
    os.remove(os.path.join(test_dir, ".hidden_file.txt"))
    os.rmdir(os.path.join(test_dir, ".hidden_dir"))
    os.remove(os.path.join(test_dir, "no_extension_file"))
    os.remove(os.path.join(test_dir, "normal_file.txt"))
    os.rmdir(test_dir)

    # Test with a non-existent directory
    print(f"\nSearching in non-existent directory: non_existent_dir")
    print(detect_hidden_files("d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\non_existent_dir"))
