import pefile

def analyze(file_path):
    try:

        pe = pefile.PE(file_path)

        # Print basic information
        print(pe.FILE_HEADER.Machine)
        print(pe.FILE_HEADER.TimeDateStamp)
        print(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        print(pe.OPTIONAL_HEADER.ImageBase)
        print(pe.OPTIONAL_HEADER.SizeOfImage)
        print(len(pe.sections))

        # Print section info
        for section in pe.sections:
            print(section.Name)
            print(section.SizeOfRawData)
            # print(section.VirtualSize)
            # print(section.Entropy)

        # Print import table
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(entry.dll)
            for imp in entry.imports:
                print(imp.name)

        # Print export table
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print(export.name)

    except pefile.PEFormatError:
        print("This isn't a PE file!")


if __name__ == "__main__":
    file_path = input("Input file path: ")
    analyze(file_path)