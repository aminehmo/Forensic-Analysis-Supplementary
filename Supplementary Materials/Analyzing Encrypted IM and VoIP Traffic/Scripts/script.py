import subprocess

# Function to extract Argus output from a given Argus file
def extract_argus_output(arg_file):
    try:
        argus_output = subprocess.check_output(['ra', '-r', arg_file])
        return argus_output.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return "Error running ra: {}".format(e)

# Function to extract address summary from a given Argus file
def extract_address_summary(arg_file):
    try:
        address_summary = subprocess.check_output(['racount', '-r', arg_file, '-M', 'addr'])
        sorted_summary = subprocess.check_output(['sort', '-nk2'], input=address_summary)
        return sorted_summary.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return "Error running racount: {}".format(e)

# Function to extract protocol summary from a given Argus file
def extract_protocol_summary(arg_file):
    try:
        protocol_summary = subprocess.check_output(['racount', '-r', arg_file, '-M', 'proto'])
        sorted_summary = subprocess.check_output(['sort', '-nk2'], input=protocol_summary)
        return sorted_summary.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return "Error running racount: {}".format(e)

# Function to extract packet size summary from a given Argus file
def extract_packet_size_summary(arg_file):
    try:
        packet_size_summary = subprocess.check_output(['rasort', '-r', arg_file, '-m', 'bytes', '-s', 'bytes'])
        sorted_summary = subprocess.check_output(['sort', '-nk1'], input=packet_size_summary)
        return sorted_summary.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return "Error running rasort: {}".format(e)

# Function to extract packet header parameters from a given Argus file
def extract_packet_header_parameters(arg_file):
    try:
        packet_header_parameters = subprocess.check_output(['rasort', '-r', arg_file, '-m', 'bytes', '-s', 'saddr', 'sport', 'daddr', 'dport'])
        return packet_header_parameters.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return "Error running rasort: {}".format(e)


if __name__ == "__main__":
    arg_file = "access_a_wa.arg"

    # Print Argus Output
    print("Argus Output:")
    print(extract_argus_output(arg_file))

    # Print Argus Output Summary
    print("\nArgus Output Summary:")

    # Packet Header Parameters
    print("\nPacket Header Parameters:")
    print(extract_packet_header_parameters(arg_file))

    # Address Summary
    print("\nAddress Summary:")
    print(extract_address_summary(arg_file))

    # Protocol Summary
    print("\nProtocol Summary:")
    print(extract_protocol_summary(arg_file))

    # Packet Size Summary
    print("\nPacket-size Summary:")
    print(extract_packet_size_summary(arg_file))























