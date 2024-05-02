#!/bin/bash

# Define the input capture file
PCAP_FILE="/home/fatima/Desktop/signal.pcapng"

# Define the output file
OUTPUT_FILE="signal_traffic_analysis1.txt"

# Check if tshark is installed
if ! command -v tshark &> /dev/null
then
    echo "tshark could not be found, please install it."
    exit
fi

# Check if the pcap file exists
if [ ! -f "$PCAP_FILE" ]; then
    echo "The pcap file $PCAP_FILE does not exist."
    exit
fi

# Extracting TLS handshake info including cipher suites
echo "Extracting TLS metadata for Signal traffic..."

tshark -r "$PCAP_FILE" -T fields \
        -e frame.time \
        -e ip.src \
        -e tcp.srcport \
        -e tls.handshake.extensions_server_name \
        -e tls.handshake.ciphersuite \
        -Y "tls.handshake.extensions_server_name contains \"signal\"" | \
        sort | uniq | \
        awk -F '\t' 'BEGIN { OFS="\t"; print "Timestamp\tSource IP\tSource Port\tSNI\tCipher Suite\tCategory?" } { gsub(/\..*/, "", $1); print $1, $2, $3, $4, $5, ($4 == "turn3.voip.signal.org" ? "Call" : "-") }' | \
        column -t -s $'\t' > "$OUTPUT_FILE"

echo "Analysis complete. Results saved in $OUTPUT_FILE"

