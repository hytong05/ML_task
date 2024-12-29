import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report
import pefile
import joblib

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
    
    DEFAULT_VALUE = -1
    
    features = {
        'Machine': getattr(pe.FILE_HEADER, 'Machine', DEFAULT_VALUE),
        'TimeDateStamp': getattr(pe.FILE_HEADER, 'TimeDateStamp', DEFAULT_VALUE),
        'AddressOfEntryPoint': getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', DEFAULT_VALUE),
        'ImageBase': getattr(pe.OPTIONAL_HEADER, 'ImageBase', DEFAULT_VALUE),
        'SizeOfImage': getattr(pe.OPTIONAL_HEADER, 'SizeOfImage', DEFAULT_VALUE),
        'NumberOfSections': len(pe.sections) if hasattr(pe, 'sections') else DEFAULT_VALUE,
    }

    for i, section in enumerate(pe.sections):
        features[f'Section_{i}_SizeOfRawData'] = getattr(section, 'SizeOfRawData', DEFAULT_VALUE)
        features[f'Section_{i}_Characteristics'] = getattr(section, 'Characteristics', DEFAULT_VALUE)
    
    im_count = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            im_count += len(entry.imports)
    features['ImportCount'] = im_count if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else DEFAULT_VALUE

    ex_count = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        ex_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    features['ExportCount'] = ex_count if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else DEFAULT_VALUE

    for name, value in features.items():
        print(f"[INFO] {name}: {value}")

    return list(features.values())

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
        max_size = max(len(item) for item in data)
        print(f"---------------{max_size}----------------")
        df = pd.DataFrame(data, columns=[f'feature_{i}' for i in range(max_size-1)] + ['label'])
        df.fillna(-1, inplace=True)
        return df
    else:
        print("[WARNING] No data extracted!")
        return pd.DataFrame()

if __name__ == "__main__":
    benign_files = get_file_list('DikeDataset/files/benign')
    malware_files = get_file_list('DikeDataset/files/malware')

    df = create_dataframe(benign_files, malware_files)
    
    # Save the DataFrame to a text file
    with open('output.txt', 'w') as f:
        f.write(df.to_string(index=False))
    print("[INFO] DataFrame saved to output.txt")

    if not df.empty:
        print("[INFO] Splitting dataset for training and testing...")
        X = df.drop('label', axis=1)
        y = df['label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42) 

        print("[INFO] Training Decision Tree Classifier...")
        clf = DecisionTreeClassifier()
        clf.fit(X_train, y_train)
        
        # Save the trained model
        joblib.dump(clf, 'decision_tree_model.joblib')
        print("[INFO] Model saved to decision_tree_model.joblib")

        print("[INFO] Making predictions...")
        y_pred = clf.predict(X_test)
        print(classification_report(y_test, y_pred))
        
        print("[INFO] Making predictions...")
        y_pred = clf.predict(X_test)
        
        # Print classification report
        print(classification_report(y_test, y_pred))
        
        # Calculate and print accuracy
        accuracy = accuracy_score(y_test, y_pred)
        print(f"[INFO] Model accuracy: {accuracy:.2f}")
    else:
        print("[ERROR] No data to train the model!")
