import os

# Import all detection modules
from anti_forensics.fake_metadata import detect_fake_metadata
from anti_forensics.hidden_file_finder import find_hidden_files
from anti_forensics.stego_detector import detect_steganography
from anti_forensics.timestomp_detector import detect_timestomping
from anti_forensics.data_wiping_detector import detect_data_wiping_patterns
from anti_forensics.encryption_detector import detect_encrypted_file
from anti_forensics.ads_detector import detect_ads

def score_anomalies(file_path):
    """
    Aggregates results from various anti-forensics detection modules
    and assigns an anomaly score to the given file.
    
    Args:
        file_path (str): The path to the file to analyze.
        
    Returns:
        dict: A dictionary containing the total anomaly score and detailed results
              from each detection module.
    """
    total_score = 0
    detailed_results = {}

    if not os.path.exists(file_path):
        return {"file_path": file_path, "total_anomaly_score": 0, "detailed_results": {"error": "File not found"}}

    # Run each detection module and assign scores

    # 1. Fake Metadata Detection
    fake_metadata_result = detect_fake_metadata(file_path)
    detailed_results["fake_metadata"] = fake_metadata_result
    if fake_metadata_result.get("is_fake_metadata"):
        total_score += 5  # Assign a score for fake metadata

    # 2. Hidden File Finder (checks if the file itself is hidden or has suspicious naming)
    # Note: find_hidden_files is designed for directories, so we adapt for a single file
    # This part might need refinement based on how find_hidden_files is structured.
    # For now, we'll check if the file name itself indicates hidden status.
    file_name = os.path.basename(file_path)
    if file_name.startswith('.') or ('.' not in file_name and file_name != ""):
        detailed_results["hidden_file_naming"] = {"is_hidden_by_name": True, "reason": "File name starts with '.' or has no extension"}
        total_score += 3
    else:
        detailed_results["hidden_file_naming"] = {"is_hidden_by_name": False}

    # 3. Steganography Detection
    stego_result = detect_steganography(file_path)
    detailed_results["steganography"] = stego_result
    if stego_result.get("is_steganography_suspected"):
        total_score += 10 # Steganography is a strong indicator

    # 4. Timestomp Detection
    timestomp_result = detect_timestomping(file_path)
    detailed_results["timestomping"] = timestomp_result
    if timestomp_result.get("is_timestomped"):
        total_score += 7 # Timestomping is a significant anomaly

    # 5. Data Wiping Detection
    data_wiping_result = detect_data_wiping_patterns(file_path)
    detailed_results["data_wiping"] = data_wiping_result
    if data_wiping_result.get("wiping_patterns_found"):
        total_score += 8 # Data wiping patterns are strong indicators

    # 6. Encryption Detection
    encryption_result = detect_encrypted_file(file_path)
    detailed_results["encryption"] = encryption_result
    if encryption_result.get("is_encrypted"):
        # Encryption itself isn't always malicious, but can be used for anti-forensics
        total_score += 4 

    # 7. ADS Detection (Windows-specific)
    ads_result = detect_ads(file_path)
    detailed_results["ads"] = ads_result
    if ads_result.get("detected_ads") and len(ads_result["detected_ads"]) > 0:
        total_score += 6 # Hidden data in ADS is a strong indicator

    return {
        "file_path": file_path,
        "total_anomaly_score": total_score,
        "detailed_results": detailed_results
    }

if __name__ == '__main__':
    # Example Usage
    # Create a dummy file for testing
    dummy_file_path = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\anomaly_test_file.txt"
    with open(dummy_file_path, 'w') as f:
        f.write("This is a test file for anomaly scoring.")

    print(f"Running anomaly scoring on: {dummy_file_path}")
    score_output = score_anomalies(dummy_file_path)
    print(score_output)

    # Clean up dummy file
    os.remove(dummy_file_path)

    # Example with a file that might trigger some detections (e.g., hidden name)
    hidden_named_file = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\.hidden_anomaly_test"
    with open(hidden_named_file, 'w') as f:
        f.write("This file has a hidden name.")
    print(f"\nRunning anomaly scoring on: {hidden_named_file}")
    score_output_hidden = score_anomalies(hidden_named_file)
    print(score_output_hidden)
    os.remove(hidden_named_file)

    # Note: For a comprehensive test, you would need to create files that specifically
    # trigger each detection mechanism and verify the scores.