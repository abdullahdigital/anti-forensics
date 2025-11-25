import os
from PIL import Image
import numpy as np

def analyze_lsb_steganography(image_path, threshold=0.05):
    """
    Analyzes the Least Significant Bits (LSB) of an image for statistical anomalies
    that might indicate steganography.
    
    This is a simplified approach. Real LSB detection often involves more complex
    statistical tests (e.g., RS analysis, chi-square attack).
    
    Args:
        image_path (str): The path to the image file.
        threshold (float): A statistical threshold for anomaly detection.
                           (e.g., a higher variance in LSBs might indicate hidden data).
                           This is a very basic heuristic.
                           
    Returns:
        dict: A dictionary indicating if LSB steganography is suspected and the anomaly score.
    """
    if not os.path.exists(image_path):
        return {"error": "File not found", "file_path": image_path}

    try:
        img = Image.open(image_path).convert('RGB')
        np_img = np.array(img)

        # Extract LSBs from each color channel
        # For an 8-bit image, the LSB is the value % 2
        lsb_red = np_img[:, :, 0] % 2
        lsb_green = np_img[:, :, 1] % 2
        lsb_blue = np_img[:, :, 2] % 2

        # Calculate the variance of the LSBs
        # In a natural image, LSBs tend to be somewhat random, but not perfectly so.
        # Hidden data often introduces a more uniform randomness or specific patterns.
        # A higher variance or a variance significantly different from expected
        # could be an indicator.
        variance_red = np.var(lsb_red)
        variance_green = np.var(lsb_green)
        variance_blue = np.var(lsb_blue)

        avg_variance = (variance_red + variance_green + variance_blue) / 3

        # Simple heuristic: if variance is very high (close to 0.25 for perfectly random bits)
        # or shows unusual patterns, it might be steganography.
        # This threshold is highly empirical and needs tuning.
        is_stego_suspected = avg_variance > threshold # Example threshold

        return {
            "file_path": image_path,
            "is_lsb_stego_suspected": is_stego_suspected,
            "lsb_variance": {
                "red": round(variance_red, 4),
                "green": round(variance_green, 4),
                "blue": round(variance_blue, 4),
                "average": round(avg_variance, 4)
            },
            "note": "LSB variance analysis is a basic heuristic. Advanced stego detection requires more sophisticated statistical methods or AI."
        }

    except FileNotFoundError:
        return {"error": "Image file not found", "file_path": image_path}
    except Exception as e:
        return {"error": str(e), "file_path": image_path}

def detect_steganography(file_path):
    """
    Main function to detect steganography using various techniques.
    
    Args:
        file_path (str): The path to the file to analyze.
        
    Returns:
        dict: A dictionary containing steganography detection results.
    """
    results = {
        "file_path": file_path,
        "is_steganography_suspected": False,
        "detection_methods": {}
    }

    # Check if the file is an image
    if not file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
        results["note"] = "File is not a common image format. Steganography detection skipped."
        return results

    lsb_analysis_result = analyze_lsb_steganography(file_path)
    results["detection_methods"]["lsb_analysis"] = lsb_analysis_result
    if lsb_analysis_result.get("is_lsb_stego_suspected"):
        results["is_steganography_suspected"] = True

    # Placeholder for AI-based steganography detection
    # AI models (e.g., CNNs) can be trained to recognize subtle patterns
    # introduced by steganography that are hard to detect with statistical methods.
    results["detection_methods"]["ai_detection_placeholder"] = {
        "status": "Not implemented",
        "note": "AI-based steganography detection would involve training deep learning models on large datasets of clean and stego images."
    }

    return results

if __name__ == '__main__':
    # Example Usage
    # Create a dummy clean image
    try:
        from PIL import Image
        dummy_clean_image = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\clean_image.png"
        img = Image.new('RGB', (100, 100), color = 'white')
        img.save(dummy_clean_image)

        print(f"Analyzing clean image: {dummy_clean_image}")
        print(detect_steganography(dummy_clean_image))
        os.remove(dummy_clean_image)

        # To simulate a stego image, you would need to embed data into it.
        # This example just shows the analysis part.
        # For a real test, you'd use a tool to embed data and then run this detector.
        print("\nNote: To properly test steganography detection, you need an image with embedded data.")
        print("This script only provides the analysis framework.")

    except ImportError:
        print("\nPillow library not installed. Skipping image steganography tests.")
        print("Please install with: pip install Pillow numpy")

    # Test with a non-image file
    dummy_text_file = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\dummy_text_for_stego.txt"
    with open(dummy_text_file, 'w') as f:
        f.write("This is a text file, not an image.")
    print(f"\nAnalyzing text file: {dummy_text_file}")
    print(detect_steganography(dummy_text_file))
    os.remove(dummy_text_file)