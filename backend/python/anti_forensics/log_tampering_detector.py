import os
import datetime
import platform

try:
    import win32evtlog
    import win32evtlogutil
    import win32security
    import win32con
except ImportError:
    win32evtlog = None
    win32evtlogutil = None
    win32security = None
    win32con = None
    print("pywin32 modules not found. Windows Event Log analysis will be skipped.")

# Assuming hash_utils.py is in the same directory and contains calculate_file_hash
from .hash_utils import calculate_file_hash

def check_log_integrity_by_hash(log_file_path, known_good_hash, hash_algorithm='sha256'):
    """
    Checks the integrity of a log file by comparing its current hash with a known good hash.

    Args:
        log_file_path (str): The path to the log file.
        known_good_hash (str): The expected hash of the log file.
        hash_algorithm (str): The hashing algorithm to use (e.g., 'md5', 'sha1', 'sha256').

    Returns:
        dict: A dictionary indicating if the integrity check passed and the current hash.
    """
    if not os.path.exists(log_file_path):
        return {"error": "Log file not found", "log_file_path": log_file_path}

    current_hash_result = calculate_file_hash(log_file_path, hash_algorithm)
    if "error" in current_hash_result:
        return {"error": f"Could not calculate hash: {current_hash_result['error']}", "log_file_path": log_file_path}

    current_hash = current_hash_result["hash_value"]
    integrity_compromised = (current_hash != known_good_hash)

    return {
        "log_file_path": log_file_path,
        "integrity_compromised": integrity_compromised,
        "current_hash": current_hash,
        "known_good_hash": known_good_hash,
        "hash_algorithm": hash_algorithm
    }

def check_log_timestamps(log_file_path):
    """
    Checks for suspicious timestamp anomalies in a log file.
    This is a basic check and might not detect sophisticated timestomping.

    Args:
        log_file_path (str): The path to the log file.

    Returns:
        dict: A dictionary indicating if timestamp anomalies are suspected and the timestamps.
    """
    if not os.path.exists(log_file_path):
        return {"error": "Log file not found", "log_file_path": log_file_path}

    stat_info = os.stat(log_file_path)
    current_time = datetime.datetime.now()

    c_time = datetime.datetime.fromtimestamp(stat_info.st_ctime)
    m_time = datetime.datetime.fromtimestamp(stat_info.st_mtime)
    a_time = datetime.datetime.fromtimestamp(stat_info.st_atime)

    suspicions = []
    if m_time > current_time:
        suspicions.append(f"Modification time ({m_time}) is in the future.")
    if c_time > current_time:
        suspicions.append(f"Creation time ({c_time}) is in the future.")
    if m_time < c_time:
        suspicions.append(f"Modification time ({m_time}) is earlier than creation time ({c_time}).")

    return {
        "log_file_path": log_file_path,
        "timestamp_anomalies_suspected": bool(suspicions),
        "reasons": suspicions,
        "timestamps": {
            "creation_time": str(c_time),
            "modification_time": str(m_time),
            "access_time": str(a_time)
        }
    }

def detect_log_tampering_ai(log_file_path):
    """
    Placeholder for AI-based log tampering detection.

    AI-based log tampering detection can involve training models to recognize deviations
    from normal log patterns, missing log entries, altered sequences, or specific
    signatures of log cleaning tools.

    Model Training Requirements:
    1.  **Dataset:** A comprehensive dataset of system logs (e.g., Windows Event Logs,
        Linux syslog, application logs) from both normal operation and scenarios where
        log tampering has occurred. This would require controlled experiments to generate
        tampered logs.
    2.  **Feature Extraction:** Features could include statistical properties of log entries
        (frequency, length, unique events), temporal patterns (time gaps, unusual timestamps),
        sequence analysis (expected vs. actual event order), and textual content analysis
        (keywords, anomalies in message structure).
    3.  **Model Architecture:** Time-series models (e.g., LSTMs, GRUs) for sequential log data,
        anomaly detection algorithms (e.g., Isolation Forest, One-Class SVM), or deep learning
        models (e.g., autoencoders for learning normal log patterns) could be used.
    4.  **Computational Resources:** Training and inference for these models may require
        significant computational resources.

    Args:
        log_file_path (str): The path to the log file to analyze.

    Returns:
        dict: A dictionary indicating the AI detection status and notes on requirements.
    """
    if not os.path.exists(log_file_path):
        return {"error": "Log file not found", "log_file_path": log_file_path}

    return {
        "log_file_path": log_file_path,
        "is_ai_tampering_suspected": False, # Placeholder result
        "confidence": 0.0, # Placeholder confidence
        "note": "AI-based log tampering detection is a placeholder. Requires a trained machine learning model. See function docstring for model training requirements."
    }

    return results

def check_windows_event_logs(log_name="Security", time_range_hours=24):
    """
    Checks Windows Event Logs for suspicious activities within a specified time range.
    Requires pywin32 library.

    Args:
        log_name (str): The name of the event log to query (e.g., "Security", "System", "Application").
        time_range_hours (int): The number of hours back from the current time to check events.

    Returns:
        dict: A dictionary containing results of the event log analysis.
    """
    if not win32evtlog:
        return {"status": "Skipped", "note": "pywin32 not installed, cannot check Windows Event Logs."}

    results = {"log_name": log_name, "suspicious_events_found": False, "events": []}
    hand = None
    try:
        hand = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total_records = win32evtlog.GetNumberOfEventLogRecords(hand)

        # Calculate the cutoff time
        cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=time_range_hours)

        events = 1
        while events:
            events = win32evtlog.ReadEventLog(hand, flags, 0)

            for event in events:
                event_time = datetime.datetime.fromtimestamp(event.TimeGenerated)
                if event_time < cutoff_time:
                    break # Stop if events are older than our time range

                # Example: Look for specific event IDs that might indicate tampering
                # Event ID 1102: The audit log was cleared
                # Event ID 1100: The event logging service has shut down
                # Event ID 517: The audit log was cleared (older systems)
                if event.EventID in [1102, 1100, 517]:
                    results["suspicious_events_found"] = True
                    results["events"].append({
                        "event_id": event.EventID,
                        "event_time": str(event_time),
                        "source": event.SourceName,
                        "computer": event.ComputerName,
                        "message": win32evtlogutil.SafeFormatMessage(event, log_name)
                    })
            else:
                continue # Only executes if the inner loop did NOT break
            break # Break the outer loop if inner loop broke

    except Exception as e:
        results["error"] = str(e)
    finally:
        if hand:
            win32evtlog.CloseEventLog(hand)
    return results

def detect_log_tampering(log_file_path, known_good_hash=None):
    """
    Detects potential log tampering by combining heuristic checks and a placeholder
    for AI-based analysis.

    Args:
        log_file_path (str): The path to the log file to analyze.
        known_good_hash (str, optional): A known good hash for integrity checking. Defaults to None.

    Returns:
        dict: A dictionary containing the log tampering detection results.
    """
    results = {"log_file_path": log_file_path}

    # Heuristic Check 1: Hash integrity
    if known_good_hash:
        hash_check_result = check_log_integrity_by_hash(log_file_path, known_good_hash)
        results["hash_integrity_check"] = hash_check_result
    else:
        results["hash_integrity_check"] = {"status": "Skipped", "note": "No known good hash provided."}

    # Heuristic Check 2: Timestamp anomalies
    timestamp_check_result = check_log_timestamps(log_file_path)
    results["timestamp_anomalies_check"] = timestamp_check_result

    # AI-based detection (placeholder integration)
    ai_tampering_result = detect_log_tampering_ai(log_file_path)
    results["ai_tampering_detection"] = ai_tampering_result

    is_tampering_suspected = (
        (known_good_hash and hash_check_result.get("integrity_compromised", False)) or
        timestamp_check_result.get("timestamp_anomalies_suspected", False) or
        ai_tampering_result.get("is_ai_tampering_suspected", False)
    )

    if platform.system() == "Windows":
        windows_event_log_check = check_windows_event_logs()
        results["windows_event_log_check"] = windows_event_log_check
        if windows_event_log_check.get("suspicious_events_found"): 
            is_tampering_suspected = True

    results["is_log_tampering_suspected"] = is_tampering_suspected

if __name__ == '__main__':
    # Example Usage
    # Create a dummy log file
    dummy_log_file = "d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\dummy.log"
    with open(dummy_log_file, 'w') as f:
        f.write("2023-01-01 10:00:00 - INFO - User logged in\n")
        f.write("2023-01-01 10:01:00 - INFO - Action performed\n")

    # Calculate its initial hash
    initial_hash_result = calculate_file_hash(dummy_log_file, 'sha256')
    known_hash = initial_hash_result["hash_value"]
    print(f"Initial hash of {dummy_log_file}: {known_hash}")

    print(f"\nAnalyzing original log file: {dummy_log_file}")
    print(detect_log_tampering(dummy_log_file, known_good_hash=known_hash))

    # Simulate tampering: modify the log file
    with open(dummy_log_file, 'a') as f:
        f.write("2023-01-01 10:02:00 - ERROR - Unauthorized access detected\n")
    print(f"\nAnalyzing tampered log file: {dummy_log_file}")
    print(detect_log_tampering(dummy_log_file, known_good_hash=known_hash))

    # Simulate tampering: change timestamp (requires os.utime)
    future_timestamp = (datetime.datetime.now() + datetime.timedelta(days=365)).timestamp()
    os.utime(dummy_log_file, (future_timestamp, future_timestamp))
    print(f"\nAnalyzing log file with future timestamp: {dummy_log_file}")
    print(detect_log_tampering(dummy_log_file, known_good_hash=known_hash))

    os.remove(dummy_log_file)

    # Analyze a non-existent file
    print(f"\nAnalyzing non-existent file: non_existent.log")
    print(detect_log_tampering("d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\non_existent.log"))
