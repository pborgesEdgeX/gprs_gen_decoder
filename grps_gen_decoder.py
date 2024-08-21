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
    """

    # Define coding scheme limits
    CODING_SCHEME_LIMITS = {
        'CS1': 22,  # Max octets for CS1
        'CS2': 32,  # Max octets for CS2
        'CS3': 38,  # Max octets for CS3
        'CS4': 52  # Max octets for CS4
    }

    def __init__(self, coding_scheme='CS1', mode='single', packet_limit=10):
        """
        Initializes the GPRSPacketGenerator with a specific coding scheme and mode.
        Args:
            coding_scheme (str): The coding scheme to be used ('CS1', 'CS2', 'CS3', or 'CS4').
            mode (str): Mode of operation, either 'single' or 'stream'.
            packet_limit (int): Number of packets to generate in both single and stream mode.
        """
        if coding_scheme not in self.CODING_SCHEME_LIMITS:
            logging.error(f"Unsupported coding scheme provided: {coding_scheme}")
            raise ValueError("Unsupported coding scheme provided.")

        if mode not in ['single', 'stream']:
            logging.error(f"Unsupported mode provided: {mode}")
            raise ValueError("Unsupported mode provided. Choose 'single' or 'stream'.")

        self.coding_scheme = coding_scheme
        self.mode = mode
        self.packet_limit = packet_limit
        self.max_payload_size = self.CODING_SCHEME_LIMITS[coding_scheme]
        self.header_format = '!BBH'
        self.header_length = struct.calcsize(self.header_format)
        self.checksum_format = '!H'
        self.checksum_length = struct.calcsize(self.checksum_format)

        logging.info(f"Initialized GPRSPacketGenerator with coding scheme: {coding_scheme} in {mode} mode")

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

    def generate_stream(self):
        """
        Generate a stream of GPRS packets according to the packet_limit, concatenate them into a single byte array.
        Returns:
            bytes: A concatenated byte array containing all the generated packets.
            list: A list of original messages for verification.
        """
        concatenated_packets = bytearray()
        messages = []

        for i in range(self.packet_limit):
            packet, message = self.generate_packet()
            concatenated_packets.extend(packet)
            messages.append(message)
            logging.info(f"Generated packet {i + 1}/{self.packet_limit} in stream mode.")

        return concatenated_packets, messages

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

    def run(self):
        """
        Run the packet generation based on the selected mode.
        Returns:
            tuple: Two elements - a byte array or a list of packets, and a list of messages.
        """
        if self.mode == 'single':
            packets = []
            messages = []
            for i in range(self.packet_limit):
                packet, message = self.generate_packet()
                packets.append(packet)
                messages.append(message)
                logging.info(f"Generated packet {i + 1}/{self.packet_limit} in single mode.")
            return packets, messages
        elif self.mode == 'stream':
            return self.generate_stream()


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

    def decode_stream(self, concatenated_packets):
        """
        Decode a concatenated stream of GPRS packets.
        Args:
            concatenated_packets (bytes): The raw byte array containing concatenated packets.
        Returns:
            list: A list of dictionaries, each containing decoded information for one packet.
        """
        packets_info = []
        i = 0

        while i < len(concatenated_packets):
            try:
                packet_length = struct.unpack('!H', concatenated_packets[i + 2:i + 4])[0]
                packet = concatenated_packets[i:i + packet_length]
                decoded_info = self.decode_packet(packet)
                packets_info.append(decoded_info)
                i += packet_length
            except Exception as e:
                logging.error(f"Error decoding packet at index {i}: {str(e)}")
                break

        return packets_info

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

        # Initialize generator in stream mode for testing
        generator = GPRSPacketGenerator(scheme, mode='stream', packet_limit=100)
        decoder = GPRSPacketDecoder(scheme)

        packets, messages = generator.run()

        if generator.mode == 'single':
            for i, packet in enumerate(packets):
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
                logging.info(f"Generated Message: {messages[i]}")
                logging.info(f"Decoded Message: {decoded_data['message']}")
                logging.info(f"Checksum Valid: {decoded_data['checksum_valid']}")

                # Verify that the original and decoded messages match
                assert messages[i] == decoded_data['message'], "Message mismatch!"
                assert decoded_data['checksum_valid'], "Checksum validation failed!"

                logging.info("Test Passed")

        elif generator.mode == 'stream':
            decoded_packets = decoder.decode_stream(packets)

            for i, decoded_data in enumerate(decoded_packets):
                logging.info("*" * 40)
                logging.info(f"Packet {i + 1} Details:")
                logging.info(f"Coding Scheme: {scheme}")
                logging.info(f"Source: {decoded_data['source']}")
                logging.info(f"Destination: {decoded_data['destination']}")
                logging.info(f"Length: {decoded_data['length']}")
                logging.info(f"P-TMSI: {decoded_data['P-TMSI']}")
                logging.info(f"TLLI: {decoded_data['TLLI']}")
                logging.info(f"Generated Message: {messages[i]}")
                logging.info(f"Decoded Message: {decoded_data['message']}")
                logging.info(f"Checksum Valid: {decoded_data['checksum_valid']}")

                # Verify that the original and decoded messages match
                assert messages[i] == decoded_data['message'], "Message mismatch!"
                assert decoded_data['checksum_valid'], "Checksum validation failed!"

                logging.info("Test Passed")

