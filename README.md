# GPRS Packet Generator and Decoder

## Overview

This project provides a Python implementation for generating and decoding GPRS (General Packet Radio Service) packets. It supports different coding schemes, including CS1, CS2, CS3, and CS4. The generated packets contain a header, a payload with P-TMSI (Packet Temporary Mobile Subscriber Identity), TLLI (Temporary Logical Link Identifier), user data, and a checksum for error detection.

## Features

- **GPRS Packet Generation**: Generate packets with random values for P-TMSI, TLLI, and user data.
- **GPRS Packet Decoding**: Decode packets to extract the source, destination, length, P-TMSI, TLLI, user data, and validate the checksum.
- **Supports Multiple Coding Schemes**: CS1, CS2, CS3, and CS4 with varying payload sizes.
- **Logging**: Detailed logging for tracking the packet generation and decoding process.
- **Checksum Validation**: Ensures the integrity of the data by calculating and verifying checksums.

## Prerequisites

- Python 3.x
- Logging is configured to output to the console.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/pborgesEdgeX/gprs_gen_decoder.git
2. Navigate to the project directory:
```bash
Copy code
cd gprs_gen_decoder
```

## Usage
The example code provided in main.py demonstrates how to generate and decode GPRS packets for each coding scheme.

```python
import logging
from gprs_packet_generator import GPRSPacketGenerator, GPRSPacketDecoder

if __name__ == "__main__":
    coding_schemes = ['CS1', 'CS2', 'CS3', 'CS4']  # All coding schemes

    for scheme in coding_schemes:
        logging.info(f"--- Testing Coding Scheme: {scheme} ---")

        generator = GPRSPacketGenerator(scheme)
        decoder = GPRSPacketDecoder(scheme)

        for i in range(10):
            # Generate and decode packet
            packet, original_message = generator.generate_packet()
            decoded_data = decoder.decode_packet(packet)

            # Log the details of the decoded packet
            logging.info(f"Packet {i + 1} Details:")
            logging.info(f"Source: {decoded_data['source']}")
            logging.info(f"Destination: {decoded_data['destination']}")
            logging.info(f"Length: {decoded_data['length']}")
            logging.info(f"P-TMSI: {decoded_data['P-TMSI']}")
            logging.info(f"TLLI: {decoded_data['TLLI']}")
            logging.info(f"Message: {decoded_data['message']}")
            logging.info(f"Checksum Valid: {decoded_data['checksum_valid']}")
            logging.info("*" * 40)

            # Verify that the original and decoded messages match
            assert original_message == decoded_data['message'], "Message mismatch!"
            assert decoded_data['checksum_valid'], "Checksum validation failed!"

            logging.info("Test Passed")
```
## Expected Output
The script will log detailed information about each packet generated and decoded, including:

- Source address
- Destination address
- Packet length
- P-TMSI
- TLLI
- User data message
- Checksum validity
If all tests pass, you will see "Test Passed" for each packet.

## Package Structure: 

 +---------------+
  |  Header     |
  +---------------+
  |  Source Address  |
  |  Destination Address |
  |  Packet Length    |
  |  Sequence Number  |
  +---------------+
  |  Payload     |
  |  P-TMSI (32 bits) |
  |  TLLI          |
  |  User Data    |
  +---------------+
  |  Checksum    |
  +---------------+

Additional details:
Detailed Structure and Data of GPRS Packets Containing P-TMSI
To decode GPRS packets containing P-TMSI, understanding the detailed structure and data format is crucial. Here is a breakdown of the key components:
1. P-TMSI
Length: 32 bits
Purpose: Temporary identifier of a GPRS subscriber for GPRS-mobility management
Allocation: Issued by the Serving GPRS Support Node (SGSN)
Uniqueness: Unique within a given Routing Area (RA)
2. TLLI (Temporary Logical Link Identifier)
Association: Associated with the P-TMSI for logical link identification
Purpose: Facilitates efficient routing and mobility management within the GPRS network
3. GPRS Packet Structure
Header: Contains source and destination addresses, packet length, and sequence number
Payload: Includes the P-TMSI, TLLI, and user data
Checksum: Used for error detection and correction
4. Coding Schemes
Types: CS1, CS2, CS3, and CS4, containing maximum data of 22, 32, 38, and 52 octets respectively
Selection: Depends on the trade-off between desired throughput and reliability
5. Transmission
RLC Segmentation: Data is segmented into RLC blocks before transmission
Header Insertions: Headers are inserted into RLC blocks for control information
Air Interface: RLC blocks are transmitted over the air interface
6. Data Rates
Theoretical Maximum: Ranges from 56 kbps to 114 kbps, depending on the coding scheme used
Practical Considerations: Actual data rates may be lower due to air interface impairments and device limitations

## Project Structure
gprs_gen_decoder/
│
├── gprs_packet_generator.py  # Contains the GPRSPacketGenerator class
├── gprs_packet_decoder.py    # Contains the GPRSPacketDecoder class
├── main.py                   # Example usage of the generator and decoder
└── README.md                 # Project documentation

## Classes

### GPRSPacketGenerator
Responsible for generating GPRS packets with the following structure:

- Header: Includes source and destination addresses, packet length.
- Payload: Contains P-TMSI, TLLI, and user data.
- Checksum: Ensures data integrity.

Methods:
__init__(coding_scheme): Initializes the generator with a specific coding scheme.
generate_random_message(length): Generates a random string of specified length.
generate_packet(): Generates a GPRS packet and returns the packet and original message.
calculate_checksum(data): Calculates the checksum for error detection.

### GPRSPacketDecoder
Responsible for decoding GPRS packets and extracting relevant data.

Methods
__init__(coding_scheme): Initializes the decoder with a specific coding scheme.
decode_packet(packet): Decodes a GPRS packet and returns the extracted data.
calculate_checksum(data): Calculates the checksum for error detection.

# Contributors
Paulo Borges (pborges7@icloud.com)


