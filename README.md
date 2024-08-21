# GPRS Packet Generator and Decoder

## Overview

This project provides a Python implementation for generating and decoding GPRS (General Packet Radio Service) packets. It supports different coding schemes, including CS1, CS2, CS3, and CS4. The generated packets contain a header, a payload with P-TMSI (Packet Temporary Mobile Subscriber Identity), TLLI (Temporary Logical Link Identifier), user data, and a checksum for error detection. The generator can operate in two modes:
- Single Mode: Generates and processes individual packets sequentially.
- Stream Mode: Generates a stream of concatenated packets which are then processed together.

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
   ```
2. Navigate to the project directory:
```bash
cd gprs_gen_decoder
```

3. Run the gprs_gen_decoder.py

Now, feel free to modify as needed:

```python
import logging
from grps_gen_decoder import GPRSPacketGenerator, GPRSPacketDecoder

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

coding_schemes = ['CS1', 'CS2', 'CS3', 'CS4']

for scheme in coding_schemes:
    logging.info(f"--- Testing Coding Scheme: {scheme} ---")

    # Initialize generator in stream mode for testing
    generator = GPRSPacketGenerator(scheme, mode='stream', packet_limit=100)
    decoder = GPRSPacketDecoder(scheme)

    packets, messages = generator.run()

    if generator.mode == 'single':
        for i, packet in enumerate(packets):
            decoded_data = decoder.decode_packet(packet)
            assert messages[i] == decoded_data['message'], "Message mismatch!"
            assert decoded_data['checksum_valid'], "Checksum validation failed!"
            logging.info("Test Passed")

    elif generator.mode == 'stream':
        decoded_packets = decoder.decode_stream(packets)
        for i, decoded_data in enumerate(decoded_packets):
            assert messages[i] == decoded_data['message'], "Message mismatch!"
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

 | Section         | Contents               |
|-----------------|------------------------|
| **Header**      |                        |
|                 | Source Address         |
|                 | Destination Address    |
|                 | Packet Length          |
|                 | Sequence Number        |
| **Payload**     |                        |
|                 | P-TMSI (32 bits)       |
|                 | TLLI                   |
|                 | User Data              |
| **Checksum**    |                        |


Additional details:
Detailed Structure and Data of GPRS Packets Containing P-TMSI
To decode GPRS packets containing P-TMSI, understanding the detailed structure and data format is crucial. Here is a breakdown of the key components:

1. P-TMSI
Length: 32 bits
Purpose: Temporary identifier of a GPRS subscriber for GPRS-mobility management
Allocation: Issued by the Serving GPRS Support Node (SGSN)
Uniqueness: Unique within a given Routing Area (RA)

### Understanding P-TMSI Numbers
The P-TMSI (Packet Temporary Mobile Subscriber Identity) is a 32-bit temporary identifier issued to a GPRS-enabled mobile device within a GSM or UMTS network. It is unique within a given Routing Area (RA) and is used by the GPRS network to page the specified mobile device.

### Key Numbers Associated with P-TMSI
- 32 bits: The length of the P-TMSI, which allows for a large number of unique identifiers within a Routing Area.
- '11' binary: The two most significant bits of the P-TMSI are always set to '11' binary to distinguish it from TMSI values, which have their two most significant bits set to '00', '01', or '10' binary.
- RAI (Routing Area Identification): Used in conjunction with the P-TMSI to uniquely identify a mobile station outside its allocated Routing Area.

### Purpose and Usage
- Paging: The GPRS network uses the P-TMSI to page a specific mobile device when attempting to deliver a call or SMS. If the subscriber does not respond to the page, they are marked as absent in both the MSC/VLR and the Home Location Register (HLR).
- Location Update: The P-TMSI aids in efficient routing of data packets within the packet-switched network and facilitates seamless mobility management as the mobile device moves across different areas.

### Allocation and Uniqueness
- SGSN Allocation: The P-TMSI is allocated by the Serving GPRS Support Node (SGSN) and is unique within a given Routing Area (RA).
- TLLI Association: The P-TMSI is associated with the Temporary Logical Link Identifier (TLLI) for logical link identification.

2. TLLI (Temporary Logical Link Identifier)
TLLI (Temporary Logical Link Identifier)
The TLLI is a crucial component in GSM and GPRS services, providing the signaling address used for communication between the user equipment and the SGSN (Serving GPRS Support Node). It is specified in the 3GPP specification 23.003.
There are four types of TLLI:
1. Local TLLI: Derived using the P-TMSI from the SGSN, valid only in the routing area associated with the P-TMSI.
2. Foreign TLLI: Derived from a P-TMSI allocated in a different routing area.
3. Random TLLI: Selected randomly by the mobile phone and used when the mobile does not have a valid P-TMSI available or when the mobile originates an anonymous access.
4. Auxiliary TLLI: Selected by the SGSN and used by the SGSN and mobile to unambiguously identify an anonymous access MM (mobility management) and PDP context.

Association: Associated with the P-TMSI for logical link identification
Purpose: The TLLI is used to provide a logical link between the MS (Mobile Station) and the SGSN. It is essential for efficient routing and mobility management within the GPRS network.

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

- `gprs_gen_decoder/`
  - `gprs_packet_generator.py`  - Contains the `GPRSPacketGenerator` class
  - `gprs_packet_decoder.py`    - Contains the `GPRSPacketDecoder` class
  - `main.py`                   - Example usage of the generator and decoder
  - `README.md`                 - Project documentation

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

## Features
- Single Mode: Generates and processes packets one by one.
- Stream Mode: Generates a continuous stream of packets, concatenated into a single byte array for processing.
- Multiple Coding Schemes: Supports CS1, CS2, CS3, and CS4 GPRS coding schemes.
- Checksum Validation: Ensures data integrity using checksum validation.

## Future Work
- Stream or single mode have not yet been stress tested, or tested with real data.

# Contributors
Paulo Borges (pborges7@icloud.com)


