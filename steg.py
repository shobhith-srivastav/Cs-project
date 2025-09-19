#!/usr/bin/env python3
"""
steg.py — simple LSB image steganography (encode/decode text into images)

Usage:
  # Encode a message into an image
  python3 steg.py encode -i cover.png -o stego.png -m "Secret message"

  # Encode message from a file
  python3 steg.py encode -i cover.png -o stego.png -mf secret.txt

  # Decode a message from an image
  python3 steg.py decode -i stego.png

Notes:
  - This uses the least-significant bit of R, G, B (3 bits per pixel).
  - A 32-bit unsigned header (big-endian) stores the message length in bytes.
  - Works best with lossless formats (PNG, BMP). JPEG may lose data due to compression.
"""

import sys
import argparse
from PIL import Image

def _bytes_to_bits(data: bytes) -> list:
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits

def _bits_to_bytes(bits: list) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Bits length not multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)
    return bytes(out)

def _capacity_pixels(img: Image.Image) -> int:
    w, h = img.size
    return w * h

def encode_image(input_path: str, output_path: str, message_bytes: bytes) -> None:
    img = Image.open(input_path)
    img = img.convert("RGBA")
    pixels = list(img.getdata())

    width, height = img.size
    total_pixels = width * height
    available_bits = total_pixels * 3
    header = len(message_bytes)
    header_bits = 32
    message_bits = len(message_bytes) * 8

    if header_bits + message_bits > available_bits:
        raise ValueError(f"Message too large for cover image. "
                         f"Available bits: {available_bits}, Needed: {header_bits + message_bits}")

    length_bytes = header.to_bytes(4, byteorder='big', signed=False)
    bitstream = _bytes_to_bits(length_bytes) + _bytes_to_bits(message_bytes)

    out_pixels = []
    bit_idx = 0
    for (r, g, b, a) in pixels:
        if bit_idx < len(bitstream):
            r = (r & ~1) | bitstream[bit_idx]; bit_idx += 1
        if bit_idx < len(bitstream):
            g = (g & ~1) | bitstream[bit_idx]; bit_idx += 1
        if bit_idx < len(bitstream):
            b = (b & ~1) | bitstream[bit_idx]; bit_idx += 1
        out_pixels.append((r, g, b, a))

    out_img = Image.new("RGBA", img.size)
    out_img.putdata(out_pixels)
    if output_path.lower().endswith((".jpg", ".jpeg")):
        out_img = out_img.convert("RGB")
    out_img.save(output_path)
    print(f"[+] Wrote stego image to: {output_path}")

def decode_image(input_path: str) -> bytes:
    img = Image.open(input_path)
    img = img.convert("RGBA")
    pixels = list(img.getdata())

    bits = []
    for (r, g, b, a) in pixels:
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)

    if len(bits) < 32:
        raise ValueError("Image too small or no hidden data found.")
    length_bits = bits[:32]
    length_bytes = _bits_to_bytes(length_bits)
    msg_len = int.from_bytes(length_bytes, byteorder='big', signed=False)
    total_msg_bits = msg_len * 8
    start = 32
    end = start + total_msg_bits
    if end > len(bits):
        raise ValueError("Image does not contain the full message or incorrect header.")
    message_bits = bits[start:end]
    message = _bits_to_bytes(message_bits)
    return message

def main(argv):
    parser = argparse.ArgumentParser(prog="steg.py", description="LSB image steganography (text)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encode", help="Encode a message into an image")
    enc.add_argument("-i", "--input", required=True, help="Cover image path (PNG/BMP recommended)")
    enc.add_argument("-o", "--output", required=True, help="Output stego image path")
    group = enc.add_mutually_exclusive_group(required=True)
    group.add_argument("-m", "--message", type=str, help="Message string to hide")
    group.add_argument("-mf", "--message-file", type=str, help="Path to file whose bytes will be hidden")

    dec = sub.add_parser("decode", help="Decode/extract message from an image")
    dec.add_argument("-i", "--input", required=True, help="Stego image path")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "encode":
            if args.message is not None:
                message_bytes = args.message.encode("utf-8")
            else:
                with open(args.message_file, "rb") as f:
                    message_bytes = f.read()
            encode_image(args.input, args.output, message_bytes)

        elif args.cmd == "decode":
            msg = decode_image(args.input)
            try:
                text = msg.decode("utf-8")
                print("[+] Extracted message (utf-8):")
                print(text)
            except UnicodeDecodeError:
                print("[+] Extracted bytes (non-utf8). Saving to extracted.bin")
                with open("extracted.bin", "wb") as f:
                    f.write(msg)
                print("Saved to extracted.bin")
    except Exception as e:
        print("[!] Error:", e)
        sys.exit(1)

if __name__ == "__main__":
    main(sys.argv[1:])
