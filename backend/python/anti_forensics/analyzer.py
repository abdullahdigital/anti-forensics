import os
import json

# Import all detector modules
from .ads_detector import detect_ads
from .timestomp_detector import detect_timestomping
from .stego_detector import detect_steganography
from .fake_metadata_detector import detect_fake_metadata
from .data_wiping_detector import detect_data_wiping
from .encryption_detector import detect_encryption
from .hidden_file_detector import detect_hidden_files
from .log_tampering_detector import detect_log_tampering
from .suspicious_rename_detector import detect_suspicious_rename
from .metadata_timeline import correlate_metadata_timeline
from .report_generator import ReportGenerator
from .usn_journal_utils import get_usn_journal_properties, read_usn_journal_records, process_usn_records_for_renames, open_volume_handle, close_volume_handle, FSCTL_READ_USN_JOURNAL, USN_REASON_RENAME_OLD_NAME, USN_REASON_RENAME_NEW_NAME, get_path_from_frn, get_file_frn
from .anomaly_scorer import AnomalyScorer

class AntiForensicsAnalyzer:
    def __init__(self):
        self.detectors = {
            "ads_detection": detect_ads,
            "timestomping_detection": detect_timestomping,
            "steganography_detection": detect_steganography,
            "fake_metadata_detection": detect_fake_metadata,
            "data_wiping_detection": detect_data_wiping,
            "encryption_detection": detect_encryption,
            "hidden_file_detection": detect_hidden_files,
            "log_tampering_detection": detect_log_tampering,
            "suspicious_rename_detection": detect_suspicious_rename,
            "metadata_timeline_correlation": correlate_metadata_timeline,
        }
        self.volume_path = "\\.\C:"  # Default to C: drive, can be configured
        self.volume_handle = None
        self.last_usn = 0
        self.usn_journal_id = None
        self.rename_events_cache = {}
        self.frn_to_path_cache = {}
        self.anomaly_scorer = AnomalyScorer()

    def analyze_file(self, file_path):
        """
        Analyzes a given file using all available anti-forensics detectors.

        Args:
            file_path (str): The path to the file to analyze.

        Returns:
            dict: A dictionary containing the aggregated results from all detectors.
        """
        if not os.path.exists(file_path):
            return {"error": "File not found", "file_path": file_path}

        results = {"file_path": file_path}

        for detector_name, detector_func in self.detectors.items():
            try:
                # Special handling for suspicious_rename_detection which needs old and new path
                # For now, we'll assume the file_path is the 'new_file_path' and 'old_file_path' is unknown
                # This needs to be refined when integrating with a system that tracks renames
                if detector_name == "suspicious_rename_detection":
                    old_file_path = file_path # Default to no rename
                    for event in self.rename_events_cache:
                        if event["new_filename"] == os.path.basename(file_path):
                            old_parent_path = self.frn_to_path_cache.get(event["old_parent_file_reference_number"])
                            if old_parent_path:
                                old_file_path = os.path.join(old_parent_path, event["old_filename"])
                            else:
                                # Fallback if old parent path not found in cache (e.g., parent was also renamed/deleted)
                                old_file_path = os.path.join(os.path.dirname(file_path), event["old_filename"])
                            break
                    detection_result = detector_func(old_file_path, file_path)
                else:
                    detection_result = detector_func(file_path)
                results[detector_name] = detection_result
            except Exception as e:
                results[detector_name] = {"error": f"Error during {detector_name}: {str(e)}"}
        
        return results

    def analyze_directory(self, directory_path):
        """
        Analyzes all files in a given directory using all available anti-forensics detectors
        and generates a comprehensive report.

        Args:
            directory_path (str): The path to the directory to analyze.

        Returns:
            ReportGenerator: An instance of ReportGenerator containing the analysis results.
        """
        if not os.path.isdir(directory_path):
            return {"error": "Directory not found", "directory_path": directory_path}

        report_generator = ReportGenerator()

        # Initialize USN Journal reading
        try:
            self.volume_handle = open_volume_handle(self.volume_path)
            if self.volume_handle:
                usn_journal_data = get_usn_journal_properties(self.volume_handle)
                if usn_journal_data:
                    self.usn_journal_id = usn_journal_data['UsnJournalID']
                    self.last_usn = usn_journal_data['NextUsn'] # Start reading from the current NextUsn

                    # Read USN records for rename events
                    # We'll read a batch of records to cover the directory analysis period
                    # For a real-time system, this would be an ongoing process
                    usn_records, _ = read_usn_journal_records(
                        self.volume_handle,
                        0, # Start from the beginning for initial scan or a specific USN for incremental
                        USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME,
                        self.usn_journal_id
                    )
                    self.rename_events_cache = process_usn_records_for_renames(usn_records)
                    print(f"Cached {len(self.rename_events_cache)} rename events from USN Journal.")
                else:
                    print(f"Could not get USN Journal properties for {self.volume_path}")
            else:
                print(f"Could not open volume handle for {self.volume_path}")
        except Exception as e:
            print(f"Error initializing USN Journal for directory analysis: {e}")
        finally:
            if self.volume_handle:
                close_volume_handle(self.volume_handle)
                self.volume_handle = None

        # Populate FRN to path cache
        for root, _, files in os.walk(directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                frn = get_file_frn(file_path)
                if frn:
                    self.frn_to_path_cache[frn] = file_path

        for root, _, files in os.walk(directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                # For directory analysis, we don't have 'old_file_path' for rename detection
                # So, we'll pass the same path for both, effectively checking for self-rename (benign)
                raw_results = self.analyze_file(file_path)
                    # Use AnomalyScorer to provide overall suspicion score.
                    raw_results["overall_suspicion_score"] = self.anomaly_scorer.score_anomalies(raw_results)
                    report_generator.add_analysis_result(file_path, raw_results)
        return report_generator

if __name__ == '__main__':
    # Example Usage
    analyzer = AntiForensicsAnalyzer()

    # Create a dummy file for testing
    dummy_file_path = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\test_file.txt"
    with open(dummy_file_path, 'w') as f:
        f.write("This is a test file for anti-forensics analysis.")
    
    print(f"Analyzing single file: {dummy_file_path}")
    single_file_results = analyzer.analyze_file(dummy_file_path)
    print(json.dumps(single_file_results, indent=4))
    os.remove(dummy_file_path)

    # Create a dummy image for steganography testing (requires Pillow)
    try:
        from PIL import Image
        dummy_image_path = "d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\test_image.png"
        img = Image.new('RGB', (100, 100), color = 'red')
        img.save(dummy_image_path)
        print(f"\nAnalyzing image file: {dummy_image_path}")
        image_results = analyzer.analyze_file(dummy_image_path)
        print(json.dumps(image_results, indent=4))
        os.remove(dummy_image_path)
    except ImportError:
        print("\nPillow library not installed. Skipping image analysis tests.")
        print("Please install with: pip install Pillow")

    # Analyze a non-existent file
    print("\nAnalyzing non-existent file:")
    non_existent_results = analyzer.analyze_file("d:\\Air University\\Semester 5\\DF Lab\\project\\project\\backend\\python\\anti_forensics\\non_existent.txt")
    print(json.dumps(non_existent_results, indent=4))

    # Analyze the current directory (excluding __pycache__)
    print(f"\nAnalyzing directory: {os.path.dirname(__file__)}")
    directory_results = analyzer.analyze_directory(os.path.dirname(__file__))
    print(json.dumps(directory_results, indent=4))
