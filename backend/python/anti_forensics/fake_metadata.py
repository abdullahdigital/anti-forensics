import os
import datetime
from PIL import Image
from PIL.ExifTags import TAGS

def get_image_exif(image_path):
    """
    Extracts EXIF data from an image file.
    """
    exif_data = {}
    try:
        with Image.open(image_path) as img:
            if hasattr(img, '_getexif'):
                info = img._getexif()
                if info:
                    for tag, value in info.items():
                        decoded = TAGS.get(tag, tag)
                        exif_data[decoded] = value
    except Exception as e:
        # Not all files are images, or may have corrupted EXIF
        pass
    return exif_data

def detect_fake_metadata(file_path):
    """
    Detects potential fake or manipulated metadata in a file.
    
    Args:
        file_path (str): The path to the file to analyze.
        
    Returns:
        dict: A dictionary indicating if fake metadata is suspected and the reasons.
    """
    suspicions = []

    if not os.path.exists(file_path):
        return {"file_path": file_path, "is_fake_metadata": False, "reason": "File not found"}

    # Check for impossible timestamps (e.g., in the future)
    stat_info = os.stat(file_path)
    current_time = datetime.datetime.now()

    c_time = datetime.datetime.fromtimestamp(stat_info.st_ctime)
    m_time = datetime.datetime.fromtimestamp(stat_info.st_mtime)
    a_time = datetime.datetime.fromtimestamp(stat_info.st_atime)

    if c_time > current_time:
        suspicions.append(f"Creation time ({c_time}) is in the future.")
    if m_time > current_time:
        suspicions.append(f"Modification time ({m_time}) is in the future.")
    if a_time > current_time:
        suspicions.append(f"Access time ({a_time}) is in the future.")

    # Check for inconsistencies in EXIF data for image files
    # This is a basic check; more advanced AI could detect patterns of manipulation
    exif_data = get_image_exif(file_path)
    if exif_data:
        # Example: Check if 'DateTimeOriginal' is significantly different from file's creation/modification time
        # This is a heuristic and might not always indicate fake metadata.
        date_original_str = exif_data.get('DateTimeOriginal')
        if date_original_str:
            try:
                # EXIF date format is typically 'YYYY:MM:DD HH:MM:SS'
                date_original = datetime.datetime.strptime(date_original_str, '%Y:%m:%d %H:%M:%S')
                time_diff = abs((date_original - c_time).total_seconds())
                # If EXIF original date is very different from file creation date (e.g., more than a day)
                if time_diff > 24 * 3600: 
                    suspicions.append(f"EXIF 'DateTimeOriginal' ({date_original}) differs significantly from file creation time ({c_time}).")
            except ValueError:
                suspicions.append(f"Invalid 'DateTimeOriginal' format in EXIF: {date_original_str}")
        
        # More advanced checks could involve:
        # - Detecting common metadata alteration tool signatures
        # - Comparing GPS coordinates with known locations (requires external data)
        # - AI models trained on datasets of authentic vs. manipulated metadata

    is_fake_metadata = bool(suspicions)

    return {
        "file_path": file_path,
        "is_fake_metadata": is_fake_metadata,
        "reasons": suspicions,
        "timestamps": {
            "creation_time": str(c_time),
            "modification_time": str(m_time),
            "access_time": str(a_time)
        },
        "exif_data": exif_data
    }

if __name__ == '__main__':
    # Example Usage
    # Create a dummy text file
    dummy_text_file = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\dummy_text.txt"
    with open(dummy_text_file, 'w') as f:
        f.write("This is a test file.")
    print(f"Analyzing text file: {dummy_text_file}")
    print(detect_fake_metadata(dummy_text_file))
    os.remove(dummy_text_file)

    # Create a dummy image file (requires Pillow library)
    try:
        from PIL import Image
        dummy_image_file = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\dummy_image.jpg"
        img = Image.new('RGB', (100, 100), color = 'red')
        img.save(dummy_image_file)

        print(f"\nAnalyzing image file: {dummy_image_file}")
        print(detect_fake_metadata(dummy_image_file))
        os.remove(dummy_image_file)

        # Simulate an image with a future creation date (for testing purposes)
        future_file = "d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\future_image.jpg"
        img_future = Image.new('RGB', (100, 100), color = 'blue')
        img_future.save(future_file)
        # Manually set a future modification time (creation time is harder to set directly)
        future_timestamp = (datetime.datetime.now() + datetime.timedelta(days=365)).timestamp()
        os.utime(future_file, (future_timestamp, future_timestamp))
        print(f"\nAnalyzing image file with future timestamp: {future_file}")
        print(detect_fake_metadata(future_file))
        os.remove(future_file)

    except ImportError:
        print("\nPillow library not installed. Skipping image metadata tests.")
        print("Please install with: pip install Pillow")

    # Test with a non-existent file
    print(f"\nAnalyzing non-existent file: non_existent.txt")
    print(detect_fake_metadata("d:\Air University\Semester 5\DF Lab\project\project\backend\python\anti_forensics\non_existent.txt"))