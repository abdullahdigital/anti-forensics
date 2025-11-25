import os
import sys

# Add the parent directory to the sys.path to allow importing anti_forensics
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from anti_forensics.router import AntiForensicsRouter

def run_anti_forensics_analysis(file_path):
    """
    Runs a comprehensive anti-forensics analysis on the given file.
    
    Args:
        file_path (str): The path to the file to analyze.
        
    Returns:
        dict: A dictionary containing the results of various anti-forensics checks.
    """
    router = AntiForensicsRouter()
    results = router.analyze_file(file_path)
    return results

if __name__ == '__main__':
    # Example usage of the main anti-forensics analysis function
    # Create a dummy file for testing
    dummy_file_path = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\main_test_file.txt"
    with open(dummy_file_path, 'w') as f:
        f.write("This is a test file for the main anti-forensics analysis function.")

    print(f"Running comprehensive anti-forensics analysis on: {dummy_file_path}")
    analysis_output = run_anti_forensics_analysis(dummy_file_path)
    print(analysis_output)

    # Clean up dummy file
    os.remove(dummy_file_path)

    # To test more thoroughly, you would create files that trigger specific detections
    # and verify the output of `run_anti_forensics_analysis`.