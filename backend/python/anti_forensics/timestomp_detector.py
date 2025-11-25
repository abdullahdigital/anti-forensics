import os
import datetime

def get_file_timestamps(file_path):
    """
    Retrieves the creation, modification, and access timestamps of a file.
    
    Args:
        file_path (str): The path to the file.
        
    Returns:
        dict: A dictionary containing 'creation_time', 'modification_time', 'access_time'
              as datetime objects, or None if the file does not exist.
    """
    if not os.path.exists(file_path):
        return None

    stat_info = os.stat(file_path)
    
    # st_ctime: creation time (on Windows), last metadata change time (on Unix)
    # st_mtime: last modification time
    # st_atime: last access time
    
    return {
        "creation_time": datetime.datetime.fromtimestamp(stat_info.st_ctime),
        "modification_time": datetime.datetime.fromtimestamp(stat_info.st_mtime),
        "access_time": datetime.datetime.fromtimestamp(stat_info.st_atime)
    }

def detect_timestomping(file_path):
    """
    Detects potential timestomping by analyzing file timestamps.
    
    Args:
        file_path (str): The path to the file to analyze.
        
    Returns:
        dict: A dictionary indicating if timestomping is suspected and the reasons.
    """
    timestamps = get_file_timestamps(file_path)

    if timestamps is None:
        return {"file_path": file_path, "is_timestomped": False, "reason": "File not found"}

    c_time = timestamps["creation_time"]
    m_time = timestamps["modification_time"]
    a_time = timestamps["access_time"]

    suspicions = []

    # Rule 1: Modification time is earlier than creation time
    # This is often a strong indicator of timestomping, though can occur with some file transfers.
    if m_time < c_time:
        suspicions.append(f"Modification time ({m_time}) is earlier than creation time ({c_time}).")

    # Rule 2: Access time is significantly older than modification/creation time
    # This could indicate an attempt to hide recent activity.
    # Define a threshold, e.g., 30 days difference
    time_difference_threshold = datetime.timedelta(days=30)
    if (c_time - a_time) > time_difference_threshold or \
       (m_time - a_time) > time_difference_threshold:
        suspicions.append(f"Access time ({a_time}) is significantly older than creation ({c_time}) or modification ({m_time}) time.")

    # Rule 3: All timestamps are identical and very recent for an old file type/location
    # This is harder to detect without context, but can be suspicious.
    # For now, we'll just check if all are identical.
    if c_time == m_time and m_time == a_time:
        suspicions.append(f"All timestamps (creation, modification, access) are identical ({c_time}). This can be suspicious if the file content suggests otherwise.")

    # Rule 4: Creation time is in the future (highly suspicious)
    if c_time > datetime.datetime.now():
        suspicions.append(f"Creation time ({c_time}) is in the future.")

    # Rule 5: Modification time is in the future (highly suspicious)
    if m_time > datetime.datetime.now():
        suspicions.append(f"Modification time ({m_time}) is in the future.")

    is_timestomped = bool(suspicions)

    return {
        "file_path": file_path,
        "is_timestomped": is_timestomped,
        "reasons": suspicions,
        "timestamps": {k: str(v) for k, v in timestamps.items()} # Convert datetime to string for output
    }

if __name__ == '__main__':
    # Example Usage
    # Create a dummy file for testing
    dummy_file_path = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\dummy_timestomp_test.txt"
    with open(dummy_file_path, 'w') as f:
        f.write("This is a test file for timestomping detection.")
    
    # Get initial timestamps
    initial_timestamps = get_file_timestamps(dummy_file_path)
    print(f"Initial timestamps: {initial_timestamps}")

    # Simulate timestomping: change modification time to be earlier than creation time
    # This requires specific OS-level calls or tools, os.utime can change mtime and atime
    # To change ctime on Windows, you often need more advanced methods or external tools.
    # For demonstration, we'll simulate a suspicious scenario.
    
    # Scenario 1: Modification time earlier than creation time
    # (This is hard to achieve directly with os.utime for ctime on Windows)
    # We'll manually create a scenario for testing the logic.
    print("\n--- Testing Scenario 1: Modification time < Creation time ---")
    # Manually create a scenario where m_time < c_time for testing purposes
    # In a real scenario, this would be detected from actual file metadata.
    test_timestamps = {
        "creation_time": datetime.datetime(2023, 1, 1, 10, 0, 0),
        "modification_time": datetime.datetime(2022, 12, 31, 9, 0, 0),
        "access_time": datetime.datetime(2023, 1, 1, 10, 0, 0)
    }
    # Temporarily override get_file_timestamps for this test
    original_get_file_timestamps = get_file_timestamps
    def mock_get_file_timestamps(path):
        if path == dummy_file_path:
            return test_timestamps
        return original_get_file_timestamps(path)
    globals()['get_file_timestamps'] = mock_get_file_timestamps

    result1 = detect_timestomping(dummy_file_path)
    print(result1)
    globals()['get_file_timestamps'] = original_get_file_timestamps # Restore original

    # Scenario 2: All timestamps identical and recent (for an assumed old file)
    print("\n--- Testing Scenario 2: All timestamps identical ---")
    # Simulate setting all timestamps to current time
    current_time = datetime.datetime.now()
    os.utime(dummy_file_path, (current_time.timestamp(), current_time.timestamp()))
    # For ctime, it's more complex. We'll rely on the os.stat().st_ctime for Windows.
    # If on Unix, st_ctime is metadata change time, not creation time.
    
    result2 = detect_timestomping(dummy_file_path)
    print(result2)

    # Clean up dummy file
    os.remove(dummy_file_path)