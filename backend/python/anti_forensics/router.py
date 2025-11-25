from anti_forensics.anomaly_scorer import score_anomalies
from anti_forensics.fake_metadata import detect_fake_metadata
from anti_forensics.hidden_file_finder import find_hidden_files
from anti_forensics.stego_detector import detect_steganography
from anti_forensics.timestomp_detector import detect_timestomping
from anti_forensics.data_wiping_detector import detect_data_wiping_patterns, analyze_slack_space
from anti_forensics.encryption_detector import detect_encrypted_file
from anti_forensics.ads_detector import detect_ads

class AntiForensicsRouter:
    def __init__(self):
        pass

    def analyze_file(self, file_path):
        results = {
            "file_path": file_path,
            "anomaly_score": score_anomalies(file_path), # Assuming score_anomalies takes file_path
            "fake_metadata_detection": detect_fake_metadata(file_path), # Assuming detect_fake_metadata takes file_path
            "hidden_files_found": find_hidden_files(file_path), # Assuming find_hidden_files takes file_path
            "steganography_detection": detect_steganography(file_path), # Assuming detect_steganography takes file_path
            "timestomping_detection": detect_timestomp_detector(file_path), # Assuming detect_timestomp_detector takes file_path
            "data_wiping_detection": detect_data_wiping_patterns(file_path), # Assuming detect_data_wiping_patterns takes file_path
            "encryption_detection": detect_encrypted_file(file_path), # Assuming detect_encrypted_file takes file_path
            "ads_detection": detect_ads(file_path) # Assuming detect_ads takes file_path
        }
        return results

    # You can add more specific methods here if needed, e.g.,
    # def get_stego_report(self, file_path):
    #     return detect_steganography(file_path)

# Example usage (for testing the router)
if __name__ == '__main__':
    router = AntiForensicsRouter()
    # Create a dummy file for testing
    dummy_test_file = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\test_file.txt"
    with open(dummy_test_file, 'w') as f:
        f.write("This is a test file for anti-forensics analysis.")

    print(f"Analyzing {dummy_test_file} using the AntiForensicsRouter:")
    analysis_results = router.analyze_file(dummy_test_file)
    print(analysis_results)

    # Clean up dummy file
    os.remove(dummy_test_file)

    # Note: For a complete test, you would need to create files that trigger
    # each of the detection mechanisms (e.g., a file with fake metadata, a stego image, etc.)
    # and ensure the individual functions are working correctly.