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

-- Source address
-- Destination address
-- Packet length
-- P-TMSI
-- TLLI
-- User data message
-- Checksum validity
If all tests pass, you will see "Test Passed" for each packet.
