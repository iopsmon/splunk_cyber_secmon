import os
import sys
from PIL import Image

def check_and_resize_images(folder_path):
    # Define expected files and their correct sizes
    expected_files = {
        "appIcon_2x.png": (72, 72),
        "appIcon.png": (36, 36),
        "appIconAlt_2x.png": (72, 72),
        "appIconAlt.png": (36, 36),
        "appLogo.png": (160, 40),
        "appLogo_2x.png": (320, 80),
    }
    
    for filename, expected_size in expected_files.items():
        file_path = os.path.join(folder_path, filename)
        if os.path.exists(file_path):
            try:
                with Image.open(file_path) as img:
                    if img.size != expected_size:
                        print(f"Resizing {filename} from {img.size} to {expected_size}")
                        img = img.resize(expected_size, Image.ANTIALIAS)
                        img.save(file_path)
                    else:
                        print(f"{filename} is already the correct size.")
            except Exception as e:
                print(f"Error processing {filename}: {e}")
        else:
            print(f"Missing: {filename}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <folder_path>")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    if not os.path.isdir(folder_path):
        print("Invalid folder path")
        sys.exit(1)
    
    check_and_resize_images(folder_path)
