import os
from scapy.all import rdpcap, TCP, UDP

def get_pcap_files_in_directory(directory):
    pcap_files = []
    for filename in os.listdir(directory):
        if filename.endswith(".pcap"):
            pcap_files.append(filename)
    return pcap_files

def process_packet(packet):
    if TCP in packet:
        payload = bytes(packet[TCP].payload)
        payload_len = len(payload)
        length_field = payload_len.to_bytes(2, byteorder='big')
        modified_payload = length_field + payload
        return modified_payload

    elif UDP in packet:
        payload = bytes(packet[UDP].payload)
        payload_len = len(payload)
        length_field = payload_len.to_bytes(2, byteorder='big')
        modified_payload = length_field + payload
        return modified_payload

def main():
    current_directory = os.getcwd()  # 获取当前工作目录
    pcap_files = get_pcap_files_in_directory(current_directory)
    
    if pcap_files:
        for filename in pcap_files:
            print(filename)
            packets = rdpcap(filename)
            modified_data = b""  # 用于存储所有修改后的数据
            for packet in packets:
                modified_payload = process_packet(packet)
                if modified_payload:
                    modified_data += modified_payload
            # 保存修改后的数据到二进制文件
            new_filename = "modified_" + os.path.splitext(filename)[0] + ".bin"
            with open(new_filename, "wb") as f:
                f.write(modified_data)
            print(f"Modified data saved to {new_filename}")
    else:
        print("No .pcap files found in the current directory.")

if __name__ == "__main__":
    main()
