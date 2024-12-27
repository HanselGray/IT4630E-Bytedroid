import struct
from zipfile import ZipFile
from time import sleep
import os

# TYPE=['Adware','Banking','Benign','SMS']
TYPE=['Benign']
PATH=f"D:\\NOTES-ARCHIVE\\MALWARE ANALYSIS\\Android malware dataset\\raw"
DESTINATION_PATH= f"D:\\NOTES-ARCHIVE\\MALWARE ANALYSIS\\Android malware dataset\\processed"

def padded(i):
    if i<10:
        return f'000{i}'
    if i<100:
        return f'00{i}'
    if i<1000:
        return f'0{i}'
    
    return i

def get_apk_list(category):
    try:
        return os.listdir(f'{PATH}/{category}')
    except Exception as e:
        return e

def convert_from_relative_to_absolute_path(path):
    return

def create_directory(category,id):
    try:
        os.mkdir(f"{DESTINATION_PATH}/{category}/{category}_{id}")
        return 1
    except FileExistsError:
        return -1
    




##################################
#       APK_PROCESSING_FUNCTION  #
##################################


def unzipping_apk(id,category,apk_file_name):
    try:
        create_directory(category,id)
        with ZipFile(f"{PATH}/{category}/{apk_file_name}","r") as apk:
            apk.extract("classes.dex",path=f"{DESTINATION_PATH}/{category}/{category}_{id}")
            apk.close()
    except Exception as e:
        return e
    return f"{DESTINATION_PATH}/{category}/{category}_{id}/classes.dex"

def padding(file_path,target_size=1536000):
    with open(file_path, "ab") as f:
        current_size = f.tell()  # Get the current file size

        if current_size < target_size:
            padding = target_size - current_size
            f.write(b'\x00' * padding)

def extract_data_section(dex_file_path, output_file_path):
    try:
        with open(dex_file_path, 'rb') as f:
            # Read the header (the first 0x70 bytes)
            header = f.read(0x70)
            
            # Unpack relevant fields from the header (little-endian format)
            # Referencing the DEX file format:
            #   - data_off (0x6C): Offset of the data section
            #   - data_size (0x68): Size of the data section
            data_size, data_off = struct.unpack_from('<II', header, 0x68)
            
            print(f"Data section offset: {data_off}")
            print(f"Data section size: {data_size}")
            
            # Seek to the data section
            f.seek(data_off)
            
            # Read the data section
            data_section = f.read(min(data_size,1500*1024))
        
        # Save the extracted data section to a file
        with open(output_file_path, 'wb') as out_file:
            out_file.write(data_section)
            out_file.close()
        
        print(f"Data section extracted to: {output_file_path}")

        os.remove(dex_file_path)

        return data_size
    except Exception as e:
        print(f"Error: {e}")
        return -1
    
    

   

# Specify paths to the input DEX file and output file for the data section
# dex_file = './test/classes_1.dex'
# output_file = 'data_section.bin'

# # Extract the data section
# # os.mkdir("banking_27")
# # with ZipFile("banking.apk","r") as apk:
# #         apk.extract("classes.dex",path=f"./banking_27")
# #         apk.close()

# extract_data_section(dex_file, output_file)
# padding(output_file,target_size=500*1024)
if __name__ == "__main__":
    # i=1
    ERROR_IDS={
        'Adware':[],
        'Benign':[],
        'Banking':[],
        'SMS':[]
    }
    for category in TYPE:
        list_apk = get_apk_list(category)
        
        for i in range(600,600+len(list_apk)):
            
            dex_path=unzipping_apk(padded(i),category,list_apk[i-600])
            dest_path=f"{DESTINATION_PATH}/{category}/{category}_{padded(i)}/data_section.bin"

            if isinstance(dex_path,Exception):
                ERROR_IDS[category].append(i)
                print(dex_path)
                print(f"Fail to extract file {list_apk[i]}")
                # sleep(2)
                continue
            else:
                print(dex_path)
                extractor=extract_data_section(dex_path,dest_path)
                if extractor==-1:
                    continue
                padding(file_path=dest_path)
            # sleep(30)
    
    for category in TYPE:
        print(category,'error ids:',ERROR_IDS[category])