import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

#Reading certificate
f = open("auth/cacsertificate.crt", "rb")
ca_cert_raw = f.read()
ca_cert = x509.load_pem_x509_certificate(
    data=ca_cert_raw, backend=default_backend()
)
ca_public_key = ca_cert.public_key()

#Extracting private/public key
try:
    with open("auth/server_private_key.pem", mode="r", encoding="utf8") as key_file:
        private_key = serialization.load_pem_private_key(
            bytes(key_file.read(), encoding="utf8"), password=None
        )
    public_key = private_key.public_key()
except Exception as e:
    print(e)

# Use private_key or public_key for encryption or decryption from now onwards

def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")

        while True:
            filename = input(
                "Enter a filename to send (enter -1 to exit):"
            ).strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2)) #Mode 2: Closes connection
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0)) # Mode 0 is sent
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(data)))
                s.sendall(data)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
