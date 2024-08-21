import binascii
import random
import logging


class AX25PacketHandler:
    """
    AX25PacketHandler is a class that handles the generation, encoding, and decoding of AX.25 packets.
    It can generate packets with random phrases as the payload and verify that the decoded message matches the original message.
    """

    def __init__(self, source, destination):
        """
        Initializes the AX25PacketHandler with source and destination callsigns.

        :param source: Source callsign (max 6 characters) and SSID, e.g., 'N0CALL-0'.
        :param destination: Destination callsign (max 6 characters) and SSID, e.g., 'APRS-0'.
        """
        self.source = source
        self.destination = destination
        self.original_messages = []  # Store original messages for verification
        self.setup_logging()
        self.short_frame_threshold = 10  # Increased threshold for short frames
        self.resync_skip_size = 50  # How far to skip when resynchronizing

    def setup_logging(self):
        """
        Sets up the logging configuration.
        """
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler()
            ]
        )

    @staticmethod
    def generate_random_phrase():
        """
        Generates a random phrase by combining words from predefined lists.

        :return: A random phrase as a string.
        """
        subjects = ["The cat", "A dog", "The quick fox", "My friend", "Our neighbor", "The scientist", "The artist", "A programmer"]
        verbs = ["jumps", "runs", "flies", "writes", "draws", "discovers", "observes", "analyzes"]
        objects = ["over the fence", "under the bridge", "in the park", "across the road", "in the lab", "at the gallery", "on the computer", "with a telescope"]

        return f"{random.choice(subjects)} {random.choice(verbs)} {random.choice(objects)}"

    def generate_ax25_frame(self, payload, control=0x03, pid=0xF0):
        """
        Generates an AX.25 frame with the given payload.

        :param payload: The payload of the frame (max 255 characters).
        :param control: Control field (default is 0x03 for UI frame).
        :param pid: PID field (default is 0xF0 for no layer 3 protocol).
        :return: AX.25 frame as a byte array.
        """

        def encode_address(callsign_ssid):
            callsign, ssid = callsign_ssid.split('-')
            callsign = callsign.ljust(6)  # Pad with spaces if less than 6 characters
            ssid = int(ssid)
            address = bytearray()
            for char in callsign:
                address.append(ord(char) << 1)  # Shift left by 1 bit
            address.append(((ssid << 1) & 0x0F) | 0x60)  # Set the SSID and command/response bits
            return address

        # Generate the address fields
        destination_address = encode_address(self.destination)
        source_address = encode_address(self.source)

        # Construct the frame without FCS
        frame = bytearray([0x7E])  # Start flag
        frame.extend(destination_address)
        frame.extend(source_address)
        frame.append(control)
        frame.append(pid)
        frame.extend(payload.encode('ascii'))

        # Calculate FCS (Frame Check Sequence)
        fcs = binascii.crc_hqx(frame[1:], 0xFFFF)
        frame.append(fcs & 0xFF)  # Append FCS low byte
        frame.append((fcs >> 8) & 0xFF)  # Append FCS high byte

        # End flag
        frame.append(0x7E)

        return frame

    @staticmethod
    def decode_ax25_frame(frame):
        """
        Decodes an AX.25 frame.

        :param frame: AX.25 frame as a byte array.
        :return: Dictionary containing the decoded fields.
        """

        def decode_address(data):
            callsign = ''
            for i in range(6):
                callsign += chr(data[i] >> 1)
            ssid = (data[6] >> 1) & 0x0F
            return f"{callsign.strip()}-{ssid}"

        if len(frame) < 18:  # Minimum length of a valid AX.25 frame (with headers and flags)
            raise ValueError("Invalid AX.25 frame: Frame too short")

        if frame[0] != 0x7E or frame[-1] != 0x7E:
            raise ValueError("Invalid AX.25 frame: Missing start/end flags")

        destination = decode_address(frame[1:8])
        source = decode_address(frame[8:15])
        control = frame[15]
        pid = frame[16]
        payload = frame[17:-3].decode('ascii')
        fcs_received = (frame[-3] << 8) | frame[-2]

        # Calculate FCS for validation
        calculated_fcs = binascii.crc_hqx(frame[1:-3], 0xFFFF)
        fcs_valid = (calculated_fcs == fcs_received)

        return {
            "Destination": destination,
            "Source": source,
            "Control Field": hex(control),
            "PID Field": hex(pid),
            "Payload": payload,
            "FCS Valid": fcs_valid
        }

    def generate_and_concatenate_packets(self, packet_count=10):
        """
        Generates and concatenates AX.25 packets into a single byte array.

        :param packet_count: Number of packets to generate and concatenate.
        :return: A single byte array containing all concatenated AX.25 packets.
        """
        concatenated_frames = bytearray()

        for i in range(packet_count):
            # Generate random phrase
            random_phrase = self.generate_random_phrase()
            self.original_messages.append(random_phrase)  # Store the original message for later verification
            logging.info(f"[Packet #{i + 1}] Generated random message: {random_phrase}")

            # Generate AX.25 frame
            ax25_frame = self.generate_ax25_frame(random_phrase)
            concatenated_frames.extend(ax25_frame)

        return concatenated_frames

    def decode_concatenated_packets(self, concatenated_frames):
        """
        Decodes concatenated AX.25 packets from a single byte array and verifies the decoded payload against the original message.

        :param concatenated_frames: A single byte array containing concatenated AX.25 packets.
        """
        i = 0
        decoded_message_count = 0
        short_frame_counter = 0

        while i < len(concatenated_frames):
            try:
                # Find start and end flag positions
                start_flag = concatenated_frames.find(b'\x7E', i)
                end_flag = concatenated_frames.find(b'\x7E', start_flag + 1)

                if start_flag == -1 or end_flag == -1:
                    break

                # Extract frame and decode
                frame = concatenated_frames[start_flag:end_flag + 1]

                # Skip the frame if it's too short or invalid
                if len(frame) < 18:
                    logging.warning(f"Skipping short frame at index {i}. Length: {len(frame)} bytes.")
                    short_frame_counter += 1

                    if short_frame_counter >= self.short_frame_threshold:
                        logging.warning(f"Too many consecutive short frames. Attempting to resynchronize...")
                        # Move the index forward by a larger amount to resync
                        i = start_flag + self.resync_skip_size
                        short_frame_counter = 0
                    else:
                        i = end_flag + 1
                    continue

                short_frame_counter = 0  # Reset counter if a valid frame is processed

                decoded_frame = self.decode_ax25_frame(frame)
                logging.info(f"[Decoded Packet #{decoded_message_count + 1}] {decoded_frame}")

                # Verify the decoded message matches the original
                if decoded_frame['Payload'] == self.original_messages[decoded_message_count]:
                    logging.info(f"[Packet #{decoded_message_count + 1}] Verification: The decoded message matches the generated message.")
                else:
                    logging.error(f"[Packet #{decoded_message_count + 1}] Verification: The decoded message does NOT match the generated message.")

                decoded_message_count += 1
                i = end_flag + 1

            except ValueError as e:
                logging.warning(f"Skipping invalid frame at index {i}. Reason: {str(e)}")
                # Resynchronize by moving to the next start flag after the current one
                i = start_flag + 1

            except Exception as e:
                logging.error(f"Unexpected error decoding packet #{decoded_message_count + 1}: {str(e)}")
                i = end_flag + 1 if end_flag != -1 else i + 1

    def process_ax25_packets(self, packet_count=10):
        """
        Generates a stream of AX.25 packets, concatenates them, and decodes the entire stream.

        :param packet_count: Number of packets to generate and process.
        """
        # Clear previous messages
        self.original_messages.clear()

        # Generate and concatenate packets
        concatenated_frames = self.generate_and_concatenate_packets(packet_count)

        # Decode the concatenated frames
        self.decode_concatenated_packets(concatenated_frames)


if __name__ == "__main__":
    # Example usage: Initialize AX25PacketHandler, generate and process 1000 concatenated packets
    source_call = "N0CALL-0"
    dest_call = "APRS-0"

    ax25_handler = AX25PacketHandler(source_call, dest_call)
    ax25_handler.process_ax25_packets(packet_count=1000)

