import os
import numpy as np
from PIL import Image
from scipy.stats import entropy
from .file_utils import is_image_file

def analyze_lsb_steganography(image_path, threshold=0.05):
    """
    Analyzes the Least Significant Bits (LSB) of an image for statistical anomalies
    that might indicate steganography. This is a basic heuristic.

    Args:
        image_path (str): The path to the image file.
        threshold (float): The variance threshold above which LSBs are considered suspicious.
                           A higher variance might indicate hidden data.

    Returns:
        dict: A dictionary containing the analysis results.
    """
    if not os.path.exists(image_path):
        return {"error": "Image file not found", "file_path": image_path}
    if not is_image_file(image_path):
        return {"error": "File is not a recognized image type", "file_path": image_path}

    try:
        img = Image.open(image_path)
        img = img.convert("RGB") # Ensure RGB format
        pixels = np.array(img)

        # Extract LSBs for each color channel
        lsb_red = (pixels[:, :, 0] & 1).flatten()
        lsb_green = (pixels[:, :, 1] & 1).flatten()
        lsb_blue = (pixels[:, :, 2] & 1).flatten()

        # Calculate variance of LSBs
        # A higher variance (closer to 0.25 for binary data) can indicate randomness
        # introduced by hidden data. For natural images, LSBs tend to be less random.
        variance_red = np.var(lsb_red)
        variance_green = np.var(lsb_green)
        variance_blue = np.var(lsb_blue)
        average_variance = (variance_red + variance_green + variance_blue) / 3

        is_stego_suspected = average_variance > threshold

        return {
            "file_path": image_path,
            "is_lsb_stego_suspected": is_stego_suspected,
            "lsb_variance": {
                "red": round(variance_red, 4),
                "green": round(variance_green, 4),
                "blue": round(variance_blue, 4),
                "average": round(average_variance, 4)
            },
            "threshold_used": threshold,
            "note": "LSB variance analysis is a basic heuristic. Advanced stego detection requires more sophisticated statistical methods or AI."
        }
    except Exception as e:
        return {"error": str(e), "file_path": image_path}

def detect_steganography_ai(image_path):
    """
    Placeholder for AI-based steganography detection.

    AI-based steganography detection typically involves training deep learning models
    (e.g., Convolutional Neural Networks - CNNs) on large datasets of both clean images
    and images embedded with various steganographic techniques.

    Model Training Requirements:
    1.  **Dataset:** A diverse dataset of images, with a significant portion containing
        hidden data using different steganographic algorithms (LSB, F5, JSteg, etc.)
        and varying payload sizes. A corresponding set of clean images is also needed.
    2.  **Feature Extraction:** CNNs can learn features directly from raw pixel data or
        from residual images (differences between the image and a denoised version).
    3.  **Model Architecture:** Specialized CNN architectures (e.g., XuNet, SRM filters + CNN)
        are often used to detect subtle statistical changes introduced by steganography.
    4.  **Computational Resources:** Training deep learning models requires substantial
        GPU resources and time.

    Args:
        image_path (str): The path to the image file.

    Returns:
        dict: A dictionary indicating the AI detection status and notes on requirements.
    """
    if not os.path.exists(image_path):
        return {"error": "Image file not found", "file_path": image_path}
    if not is_image_file(image_path):
        return {"error": "File is not a recognized image type", "file_path": image_path}

    # In a real implementation, you would load a pre-trained AI model here
    # and use it to predict the likelihood of steganography.
    # Example:
    # try:
    #     model = load_stego_detection_model('path/to/your/ai_model.h5')
    #     image_data = preprocess_image_for_ai(image_path)
    #     prediction = model.predict(image_data)
    #     is_ai_stego_suspected = prediction[0][0] > 0.5 # Example threshold
    #     confidence = float(prediction[0][0])
    #     return {
    #         "file_path": image_path,
    #         "is_ai_stego_suspected": is_ai_stego_suspected,
    #         "confidence": confidence,
    #         "note": "AI-based steganography detection performed."
    #     }
    # except Exception as e:
    #     return {"error": f"AI detection failed: {str(e)}", "file_path": image_path}

    return {
        "file_path": image_path,
        "is_ai_stego_suspected": False, # Placeholder result
        "confidence": 0.0, # Placeholder confidence
        "note": "AI-based steganography detection is a placeholder. Requires a trained deep learning model (e.g., CNN) and appropriate libraries (TensorFlow/PyTorch). See function docstring for model training requirements."
    }

def detect_steganography(file_path):
    """
    Combines LSB analysis and AI-based detection (placeholder) to detect steganography.

    Args:
        file_path (str): The path to the file to analyze.

    Returns:
        dict: A dictionary containing the combined steganography detection results.
    """
    if not is_image_file(file_path):
        return {
            "file_path": file_path,
            "is_steganography_suspected": False,
            "note": "File is not an image, steganography detection skipped."
        }

    lsb_results = analyze_lsb_steganography(file_path)
    ai_results = detect_steganography_ai(file_path)

    is_steganography_suspected = lsb_results.get("is_lsb_stego_suspected", False) or \
                                 ai_results.get("is_ai_stego_suspected", False)

    return {
        "file_path": file_path,
        "is_steganography_suspected": is_steganography_suspected,
        "detection_methods": {
            "lsb_analysis": lsb_results,
            "ai_detection": ai_results
        },
        "overall_note": "Combined results from LSB analysis and AI (placeholder) for steganography detection."
    }

if __name__ == '__main__':
    # Example Usage
    # Create a dummy image for testing
    from PIL import Image, ImageDraw

    dummy_image_path = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\dummy_clean_image.png"
    stego_image_path = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\dummy_stego_image.png"

    # Create a simple clean image
    img = Image.new('RGB', (100, 100), color = 'red')
    d = ImageDraw.Draw(img)
    d.text((10,10), "Hello", fill=(255,255,0))
    img.save(dummy_image_path)

    print(f"Analyzing clean image: {dummy_image_path}")
    clean_result = detect_steganography(dummy_image_path)
    print(clean_result)

    # Simulate a steganographic image (very basic LSB modification for demonstration)
    # In a real scenario, you'd use a steganography tool to embed data.
    # This simple modification might not always trigger the LSB variance detector reliably
    # as it depends on the threshold and the nature of the modification.
    stego_img = Image.open(dummy_image_path)
    pixels = np.array(stego_img)
    # Modify some LSBs (e.g., change the last bit of some red pixels)
    for i in range(10):
        for j in range(10):
            pixels[i, j, 0] = pixels[i, j, 0] ^ 1 # Flip LSB of red channel
    Image.fromarray(pixels).save(stego_image_path)

    print(f"\nAnalyzing stego image: {stego_image_path}")
    stego_result = detect_steganography(stego_image_path)
    print(stego_result)

    # Example for a non-image file
    non_image_file = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\test_non_image.txt"
    with open(non_image_file, 'w') as f:
        f.write("This is not an image.")
    print(f"\nAnalyzing non-image file: {non_image_file}")
    non_image_result = detect_steganography(non_image_file)
    print(non_image_result)

    # Clean up dummy files
    os.remove(dummy_image_path)
    os.remove(stego_image_path)
    os.remove(non_image_file)
