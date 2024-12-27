import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report
import pefile

def get_file_list(directory):
    print(f"[INFO] Scanning directory: {directory}")
    filelist = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".exe"):
                full_path = os.path.join(root, file)
                filelist.append(full_path)
                print(f"[INFO] Found file: {full_path}")
    print(f"[INFO] Total files found: {len(filelist)}")
    return filelist

def extract_feature(file):
    print(f"[INFO] Extracting features from: {file}")
    try:
        with open(file, 'rb') as f:
            pe = pefile.PE(data=f.read())
    except pefile.PEFormatError:
        print(f"[ERROR] PEFormatError - Skipping file: {file}")
        return None
    except Exception as e:
        print(f"[ERROR] Unexpected error reading {file}: {str(e)}")
        return None

    feature = [
        pe.FILE_HEADER.Machine,
        pe.FILE_HEADER.TimeDateStamp,
        pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        pe.OPTIONAL_HEADER.ImageBase,
        pe.OPTIONAL_HEADER.SizeOfImage,
        len(pe.sections),
    ]   

    for section in pe.sections:
        feature.extend([
            section.SizeOfRawData,
            section.Characteristics,
        ])
    
    im_count = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            im_count += len(entry.imports)
    feature.append(im_count)

    ex_count = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        ex_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    feature.append(ex_count)

    return feature

def create_dataframe(benign_files, malware_files):
    data = []
    
    print("[INFO] Processing benign files...")
    for file in benign_files:
        features = extract_feature(file)
        if features:
            data.append(features + [0])

    print("[INFO] Processing malware files...")
    for file in malware_files:
        features = extract_feature(file)
        if features:
            data.append(features + [1])

    if data:
        return pd.DataFrame(data, columns=[f'feature_{i}' for i in range(len(data[0])-1)] + ['label'])
    else:
        print("[WARNING] No data extracted!")
        return pd.DataFrame()

if __name__ == "__main__":
    benign_files = get_file_list('DatasetTest/Benign')
    malware_files = get_file_list('DatasetTest/Malware')

    df = create_dataframe(benign_files, malware_files)

    if not df.empty:
        print("[INFO] Splitting dataset for training and testing...")
        X = df.drop('label', axis=1)
        y = df['label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42) 

        print("[INFO] Training Decision Tree Classifier...")
        clf = DecisionTreeClassifier()
        clf.fit(X_train, y_train)

        print("[INFO] Making predictions...")
        y_pred = clf.predict(X_test)
        print(classification_report(y_test, y_pred))
    else:
        print("[ERROR] No data to train the model!")
