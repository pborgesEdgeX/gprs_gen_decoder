import logging
import random
import string
import struct

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class GPRSPacketGenerator:
    """
    GPRSPacketGenerator is responsible for generating GPRS packets containing a header,
    payload with P-TMSI and TLLI, user data, and a checksum.
    The generated packets adhere to different coding schemes: CS1, CS2, CS3, and CS4.
    It follows the following structure:
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

    """

    # Define coding scheme limits
    CODING_SCHEME_LIMITS = {
        'CS1': 22,  # Max octets for CS1
        'CS2': 32,  # Max octets for CS2
        'CS3': 38,  # Max octets for CS3
        'CS4': 52  # Max octets for CS4
    }

    def __init__(self, coding_scheme='CS1'):
        """
        Initializes the GPRSPacketGenerator with a specific coding scheme.
        Args:
            coding_scheme (str): The coding scheme to be used ('CS1', 'CS2', 'CS3', or 'CS4').
        """
        if coding_scheme not in self.CODING_SCHEME_LIMITS:
            logging.error(f"Unsupported coding scheme provided: {coding_scheme}")
            raise ValueError("Unsupported coding scheme provided.")

        self.coding_scheme = coding_scheme
        self.max_payload_size = self.CODING_SCHEME_LIMITS[coding_scheme]
        self.header_format = '!BBH'
        self.header_length = struct.calcsize(self.header_format)
        self.checksum_format = '!H'
        self.checksum_length = struct.calcsize(self.checksum_format)

        logging.info(f"Initialized GPRSPacketGenerator with coding scheme: {coding_scheme}")

    def generate_random_message(self, length):
        """
        Generate a random string of specified length.
        Args:
            length (int): The length of the random string.
        Returns:
            str: The generated random string.
        """
        message = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        logging.debug(f"Generated random message of length {length}: {message}")
        return message

    def generate_packet(self):
        """
        Generate a GPRS packet with random P-TMSI, TLLI, and payload.
        Returns:
            tuple: A tuple containing the generated packet (bytes) and the original message (str).
        """
        source = random.randint(1, 255)
        destination = random.randint(1, 255)
        ptmsi = random.randint(0x00000001, 0xFFFFFFFF)
        tlli = random.randint(0x00000001, 0xFFFFFFFF)
        message_length = self.max_payload_size - 8  # 8 bytes reserved for P-TMSI and TLLI
        message = self.generate_random_message(message_length)

        payload = struct.pack('!II', ptmsi, tlli) + message.encode('utf-8')
        length = len(payload) + self.header_length + self.checksum_length
        packet = struct.pack(self.header_format, source, destination, length) + payload
        checksum = self.calculate_checksum(packet)
        packet += struct.pack(self.checksum_format, checksum)

        logging.info(f"Generated packet with source: {source}, destination: {destination}, length: {length}")
        return packet, message

    def calculate_checksum(self, data):
        """
        Calculate the checksum for error detection.
        Args:
            data (bytes): The data for which to calculate the checksum.
        Returns:
            int: The calculated checksum.
        """
        checksum = sum(data) & 0xFFFF
        logging.debug(f"Calculated checksum: {checksum}")
        return checksum


class GPRSPacketDecoder:
    """
    GPRSPacketDecoder is responsible for decoding GPRS packets to extract the
    P-TMSI, TLLI, user data, and validating the checksum.
    """

    # Define coding scheme limits
    CODING_SCHEME_LIMITS = {
        'CS1': 22,  # Max octets for CS1
        'CS2': 32,  # Max octets for CS2
        'CS3': 38,  # Max octets for CS3
        'CS4': 52  # Max octets for CS4
    }

    def __init__(self, coding_scheme='CS1'):
        """
        Initializes the GPRSPacketDecoder with a specific coding scheme.
        Args:
            coding_scheme (str): The coding scheme to be used ('CS1', 'CS2', 'CS3', or 'CS4').
        """
        if coding_scheme not in self.CODING_SCHEME_LIMITS:
            logging.error(f"Unsupported coding scheme provided: {coding_scheme}")
            raise ValueError("Unsupported coding scheme provided.")

        self.coding_scheme = coding_scheme
        self.max_payload_size = self.CODING_SCHEME_LIMITS[coding_scheme]
        self.header_format = '!BBH'
        self.header_length = struct.calcsize(self.header_format)
        self.checksum_format = '!H'
        self.checksum_length = struct.calcsize(self.checksum_format)

        logging.info(f"Initialized GPRSPacketDecoder with coding scheme: {coding_scheme}")

    def decode_packet(self, packet):
        """
        Decode a GPRS packet to extract the P-TMSI, TLLI, and other relevant data.
        Args:
            packet (bytes): The raw GPRS packet.
        Returns:
            dict: A dictionary containing decoded information such as source, destination,
                  length, P-TMSI, TLLI, message, and checksum validity.
        """
        header_data = packet[:self.header_length]
        source, destination, length = struct.unpack(self.header_format, header_data)

        payload_start = self.header_length
        payload_end = min(payload_start + self.max_payload_size, len(packet) - self.checksum_length)

        ptmsi = struct.unpack('!I', packet[payload_start:payload_start + 4])[0]
        tlli = struct.unpack('!I', packet[payload_start + 4:payload_start + 8])[0]
        message = packet[payload_start + 8:payload_end].decode('utf-8')

        checksum_start = payload_end
        received_checksum = \
            struct.unpack(self.checksum_format, packet[checksum_start:checksum_start + self.checksum_length])[0]
        calculated_checksum = self.calculate_checksum(packet[:checksum_start])
        checksum_valid = received_checksum == calculated_checksum

        logging.info(
            f"Decoded packet with source: {source}, destination: {destination}, length: {length}, checksum valid: {checksum_valid}")
        return {
            'source': source,
            'destination': destination,
            'length': length,
            'P-TMSI': ptmsi,
            'TLLI': tlli,
            'message': message,
            'checksum_valid': checksum_valid
        }

    def calculate_checksum(self, data):
        """
        Calculate the checksum for error detection.
        Args:
            data (bytes): The data for which to calculate the checksum.
        Returns:
            int: The calculated checksum.
        """
        checksum = sum(data) & 0xFFFF
        logging.debug(f"Calculated checksum: {checksum}")
        return checksum


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
            logging.info("*" * 40)
            logging.info(f"Packet {i + 1} Details:")
            logging.info(f"Coding Scheme: {scheme}")
            logging.info(f"Source: {decoded_data['source']}")
            logging.info(f"Destination: {decoded_data['destination']}")
            logging.info(f"Length: {decoded_data['length']}")
            logging.info(f"P-TMSI: {decoded_data['P-TMSI']}")
            logging.info(f"TLLI: {decoded_data['TLLI']}")
            logging.info(f"Generated Packet: {packet}")
            logging.info(f"Generated Message: {original_message}")
            logging.info(f"Decoded Message: {decoded_data['message']}")
            logging.info(f"Checksum Valid: {decoded_data['checksum_valid']}")

            # Verify that the original and decoded messages match
            assert original_message == decoded_data['message'], "Message mismatch!"
            assert decoded_data['checksum_valid'], "Checksum validation failed!"

            logging.info("Test Passed")

