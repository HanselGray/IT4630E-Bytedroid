import zipfile
import struct
import os
import glob

def extract_apk(apk_path, output_dir):
    """Extracts an APK file to the specified output directory."""
    with zipfile.ZipFile(apk_path, 'r') as apk:
        apk.extractall(output_dir)
    print(f"Extracted APK contents to {output_dir}")

def parse_dex_header(dex_file_path):
    """Parses the header information of a DEX file and prints it."""
    with open(dex_file_path, 'rb') as f:
        data = f.read()

        # Ensure file starts with the DEX magic number
        magic = data[:8]
        if magic[:3] != b'dex':
            raise ValueError(f"Not a valid DEX file: {dex_file_path}")

        print(f"\nDEX Header Information for {os.path.basename(dex_file_path)}:")

        # Parse header fields based on the DEX format
        header = {
            'magic': magic,
            'checksum': struct.unpack('<I', data[8:12])[0],
            'signature': data[12:32].hex(),
            'file_size': struct.unpack('<I', data[32:36])[0],
            'header_size': struct.unpack('<I', data[36:40])[0],
            'endian_tag': struct.unpack('<I', data[40:44])[0],
            'link_size': struct.unpack('<I', data[44:48])[0],
            'link_offset': struct.unpack('<I', data[48:52])[0],
            'map_offset': struct.unpack('<I', data[52:56])[0],
            'string_ids_size': struct.unpack('<I', data[56:60])[0],
            'string_ids_offset': struct.unpack('<I', data[60:64])[0],
            'type_ids_size': struct.unpack('<I', data[64:68])[0],
            'type_ids_offset': struct.unpack('<I', data[68:72])[0],
            'proto_ids_size': struct.unpack('<I', data[72:76])[0],
            'proto_ids_offset': struct.unpack('<I', data[76:80])[0],
            'field_ids_size': struct.unpack('<I', data[80:84])[0],
            'field_ids_offset': struct.unpack('<I', data[84:88])[0],
            'method_ids_size': struct.unpack('<I', data[88:92])[0],
            'method_ids_offset': struct.unpack('<I', data[92:96])[0],
            'class_defs_size': struct.unpack('<I', data[96:100])[0],
            'class_defs_offset': struct.unpack('<I', data[100:104])[0],
            'data_size': struct.unpack('<I', data[104:108])[0],
            'data_offset': struct.unpack('<I', data[108:112])[0],
        }

        for key, value in header.items():
            print(f"{key}: {value}")

        return header

def extract_data_section(dex_file_path, data_offset, data_size, output_dir):
    """Extracts the data section from a DEX file and splits it into chunks of 512,000 bytes."""
    with open(dex_file_path, 'rb') as f:
        f.seek(data_offset)
        data_section = f.read(data_size)

    chunk_size = 512000
    num_chunks = (len(data_section) + chunk_size - 1) // chunk_size # Calculate number of chunks
    print(num_chunks)
    for i in range(num_chunks):
        chunk = data_section[i * chunk_size:(i + 1) * chunk_size]
        output_file = os.path.join(
            output_dir, f"{os.path.basename(dex_file_path).replace('.dex', '')}_data_section_chunk_{i + 1}.bin"
        )
        with open(output_file, 'wb') as out_f:
            out_f.write(chunk + b'\x00' * (chunk_size - len(chunk)))  # Pad with NULL if needed

        print(f"Data section chunk {i + 1} saved to {output_file} (Size: {len(chunk)} bytes)")

if __name__ == "__main__":
    # apk_path = input("Enter the path to the APK file: ").strip()
    output_dir = "test/c758dfe4158ea4f7f91eb5a145ebbfe2ccb704badef9e6f54b00ab37fe6ee8dc/"

    # # Step 1: Extract APK
    # extract_apk(apk_path, output_dir)

    # Step 2: Locate all classes.dex files
    dex_files = glob.glob(os.path.join(output_dir, "classes*.dex"))
    if not dex_files:
        print("No classes.dex files found in the APK.")
    else:
        for dex_file_path in dex_files:
            # Step 3: Parse DEX header
            print(dex_file_path)
            header = parse_dex_header(dex_file_path)

            # Step 4: Extract data section and save it
            data_section = extract_data_section(
                dex_file_path, header['data_offset'], header['data_size'], output_dir
            )

