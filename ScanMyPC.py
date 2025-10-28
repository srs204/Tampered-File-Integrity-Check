import os
import sys
import argparse
import numpy as np
from tensorflow.keras.models import load_model
from peview_extraction import pe_extract

def scan_file(filepath, model):
    """Scan a single file and predict if it is malware."""
    try:
        features = pe_extract(filepath)
        prediction = model.predict(features)
        return prediction[0][0]
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return None

def scan_directory(directory, model, verbose=False):
    """Recursively scan a directory for executable files."""
    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.exe', '.dll', '.sys')):
                filepath = os.path.join(root, file)
                prediction = scan_file(filepath, model)
                if prediction is not None:
                    result = {
                        "file": filepath,
                        "malware": prediction > 0.5
                    }
                    results.append(result)
                    if verbose:
                        print(f"Scanned: {filepath} | Malware: {result['malware']}")
    return results

def save_results(results, output_file):
    """Save the scan results to a CSV file."""
    import csv
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["File", "Malware"])
        for result in results:
            writer.writerow([result["file"], result["malware"]])

def main():
    if len(sys.argv) == 1:
        sys.argv = ["ScanMyPC.py", "C:", "-v"]  # Replace this with your test directory path

    parser = argparse.ArgumentParser(description="Scan your PC for malware using a pre-trained model.")
    parser.add_argument("directory", help="Directory or drive to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-o", "--output", help="Output CSV file for results", default="scan_results.csv")
    args = parser.parse_args()

    # Loading the pre-trained model
    try:
        model = load_model("ScanMyPC_Training.h5")
    except Exception as e:
        print(f"Error loading model: {e}")
        sys.exit(1)

    # Scanning the directory
    print(f"Scanning directory: {args.directory}")
    results = scan_directory(args.directory, model, verbose=args.verbose)

    # Saving results to a CSV file
    save_results(results, args.output)
    print(f"Scan completed. Results saved to {args.output}.")

    # Summary
    malware_files = [r for r in results if r["malware"]]
    print(f"Total files scanned: {len(results)}")
    print(f"Malware detected: {len(malware_files)}")
    for malware in malware_files:
        print(f"Malware found: {malware['file']}")


if __name__ == "__main__":
    main()
