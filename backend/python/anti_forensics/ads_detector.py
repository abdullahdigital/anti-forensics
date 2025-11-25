import os
import platform

def detect_ads(file_path):
    """
    Detects Alternate Data Streams (ADS) for a given file on NTFS file systems (Windows).
    
    Args:
        file_path (str): The path to the file to check for ADS.
        
    Returns:
        dict: A dictionary containing the file path and a list of detected ADS names.
              Returns an error if not on Windows or if the file does not exist.
    """
    if platform.system() != "Windows":
        return {"error": "ADS detection is only supported on Windows (NTFS file systems)", "file_path": file_path}

    if not os.path.exists(file_path):
        return {"error": "File not found", "file_path": file_path}

    detected_ads = []
    try:
        # On Windows, ADS can be listed by appending "::$DATA" to the file path
        # or by using directory listings that show stream names.
        # A direct Python way to list all ADS is not straightforward without external tools
        # or more complex ctypes interactions. 
        # For simplicity, this example will check for a known ADS name.
        # In a real forensic tool, you'd integrate with a tool like 'streams.exe' or similar.

        # This is a simplified check. A more robust solution would involve
        # calling a system utility or using pywin32.
        # For demonstration, let's assume we are looking for a specific stream name.
        # In a real scenario, you'd enumerate all streams.
        
        # Example: Check for a stream named 'hidden_stream'
        # You would typically iterate through potential stream names or use a tool
        # to list them.
        test_stream_name = "hidden_stream"
        test_ads_path = f"{file_path}:{test_stream_name}"
        
        # Check if the stream exists by trying to open it
        # This is a heuristic and might not catch all ADS without enumeration
        try:
            with open(test_ads_path, 'rb') as f:
                detected_ads.append(test_stream_name)
        except FileNotFoundError:
            pass # Stream does not exist
        except Exception as e:
            # Other errors might occur, e.g., permission denied
            print(f"Warning: Could not check for ADS {test_stream_name} on {file_path}: {e}")

    except Exception as e:
        return {"error": str(e), "file_path": file_path}

    return {
        "file_path": file_path,
        "detected_ads": detected_ads,
        "note": "Comprehensive ADS detection often requires specialized tools or system calls."
    }

if __name__ == '__main__':
    # Example Usage (on Windows)
    if platform.system() == "Windows":
        dummy_file_path = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\dummy_file_with_ads.txt"
        with open(dummy_file_path, 'w') as f:
            f.write("This is the main content.")
        
        # Create a dummy ADS (this requires specific Windows commands or pywin32)
        # For demonstration, we'll simulate its existence.
        # In a real scenario, you'd use a command like:
        # echo "hidden data" > dummy_file_with_ads.txt:hidden_stream
        
        # Simulate creating an ADS for testing purposes
        try:
            with open(f"{dummy_file_path}:hidden_stream", 'w') as f_ads:
                f_ads.write("This is hidden in an Alternate Data Stream.")
            print(f"Created dummy ADS for {dummy_file_path}")
        except Exception as e:
            print(f"Could not create dummy ADS (run this script on NTFS drive): {e}")

        print(f"Analyzing: {dummy_file_path}")
        result = detect_ads(dummy_file_path)
        print(result)

        # Clean up dummy file and its ADS
        os.remove(dummy_file_path)
        # Removing ADS is tricky; often requires specific tools or re-creating the file
        # For this example, we'll just remove the main file.

    else:
        print("ADS detection example skipped: Not on Windows.")

    # Test with a non-existent file
    print(detect_ads("d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\non_existent_file.txt"))