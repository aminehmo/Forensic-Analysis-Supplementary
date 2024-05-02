import json

# Replace this with the path to your HAR file
har_file_path = '/home/fatima/Desktop/WEB.har'

# Open the HAR file
with open(har_file_path, 'r', encoding='utf-8-sig') as file:
    har_data = json.loads(file.read())

# Write the extracted information to a text file
with open('whatsapp_image_content_info.txt', 'w', encoding='utf-8') as file:
    # Write the headers
    file.write("Protocol, Host, URL, Content-Type\n")

    # Process each entry in the HAR file
    for entry in har_data['log']['entries']:
        request = entry['request']
        response = entry['response']
        
        # URL
        url = request['url']

        # Skip entries that don't contain 'whatsapp' in the URL
        if 'whatsapp' not in url:
            continue
        
        # Protocol (assuming HTTP/1.1, HTTP/2, etc.)
        protocol = request['httpVersion']
        
        # Host (extract from the headers list)
        host = next((header['value'] for header in request['headers'] if header['name'].lower() == 'host'), 'No host found')

        # Content-Type (from the response headers)
        content_type = next((header['value'] for header in response['headers'] if header['name'].lower() == 'content-type'), 'No Content-Type found')

        # Only write out entries with the desired content types
        if content_type.startswith('image/webp') or content_type.startswith('image/jpeg') or content_type.startswith('image/gif'):
            # Write the extracted information to the output file
            file.write(f"{protocol}, {host}, {url}, {content_type}\n")

print("Extraction complete. Results saved in whatsapp_image_content_info.txt")

