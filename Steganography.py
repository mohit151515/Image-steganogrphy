import gradio as gr
import cv2
import numpy as np
import hashlib
from PIL import Image
from io import BytesIO

class SecureImageSteganography:
    def __init__(self):
        pass

    def hash_password(self, password):
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def validate_image_capacity(self, img, msg_length):
        max_capacity = img.shape[0] * img.shape[1] * 3
        return msg_length < max_capacity

    def encrypt_message(self, img, msg, password):
        encrypted_img = img.copy()
        hashed_password = self.hash_password(password).encode('utf-8')
        msg_bytes = msg.encode('utf-8')
        msg_length = len(msg_bytes)

        if not self.validate_image_capacity(img, msg_length + len(hashed_password) + 5):
            raise ValueError("Message too large for the image")

        length_bytes = msg_length.to_bytes(4, byteorder='big')
        n, m, z = 0, 0, 0

        for byte in hashed_password:
            encrypted_img[n, m, z] = byte
            z = (z + 1) % 3
            if z == 0:
                m += 1
                if m == img.shape[1]:
                    m = 0
                    n += 1

        encrypted_img[n, m, z] = 255
        z = (z + 1) % 3
        if z == 0:
            m += 1
            if m == img.shape[1]:
                m = 0
                n += 1

        for byte in length_bytes:
            encrypted_img[n, m, z] = byte
            z = (z + 1) % 3
            if z == 0:
                m += 1
                if m == img.shape[1]:
                    m = 0
                    n += 1

        encrypted_img[n, m, z] = 255
        z = (z + 1) % 3
        if z == 0:
            m += 1
            if m == img.shape[1]:
                m = 0
                n += 1

        for byte in msg_bytes:
            encrypted_img[n, m, z] = byte
            z = (z + 1) % 3
            if z == 0:
                m += 1
                if m == img.shape[1]:
                    m = 0
                    n += 1

        return encrypted_img

    def decrypt_message(self, img, input_password):
        try:
            n, m, z = 0, 0, 0
            retrieved_hash_bytes = bytearray()

            while True:
                pixel_value = img[n, m, z]
                if pixel_value == 255:
                    break
                retrieved_hash_bytes.append(pixel_value)
                z = (z + 1) % 3
                if z == 0:
                    m += 1
                    if m == img.shape[1]:
                        m = 0
                        n += 1

            retrieved_hash = bytes(retrieved_hash_bytes).decode('utf-8', errors='ignore')
            input_hash = self.hash_password(input_password)

            if input_hash.strip() != retrieved_hash.strip():
                return "Error: Incorrect Password"

            z = (z + 1) % 3
            if z == 0:
                m += 1
                if m == img.shape[1]:
                    m = 0
                    n += 1

            length_bytes = bytearray()
            for _ in range(4):
                length_bytes.append(img[n, m, z])
                z = (z + 1) % 3
                if z == 0:
                    m += 1
                    if m == img.shape[1]:
                        m = 0
                        n += 1

            msg_length = int.from_bytes(length_bytes, byteorder='big')
            if msg_length <= 0 or msg_length > img.shape[0] * img.shape[1] * 3:
                return "Error: Invalid message length"

            z = (z + 1) % 3
            if z == 0:
                m += 1
                if m == img.shape[1]:
                    m = 0
                    n += 1

            msg_bytes = bytearray()
            for _ in range(msg_length):
                msg_bytes.append(img[n, m, z])
                z = (z + 1) % 3
                if z == 0:
                    m += 1
                    if m == img.shape[1]:
                        m = 0
                        n += 1

            return msg_bytes.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"Decryption Error: {str(e)}"

steg = SecureImageSteganography()

def encrypt(img, message, password):
    img_array = np.array(img)
    encrypted_img = steg.encrypt_message(img_array, message, password)
    return Image.fromarray(encrypted_img).convert("RGB")

def decrypt(img, password):
    img_array = np.array(img)
    return steg.decrypt_message(img_array, password)

encrypt_interface = gr.Interface(
    fn=encrypt, 
    inputs=["image", "text", "text"], 
    outputs=gr.Image(type="numpy", format="png"), 
    title="Image Encryption"
)

decrypt_interface = gr.Interface(
    fn=decrypt, 
    inputs=["image", "text"], 
    outputs="text", 
    title="Image Decryption"
)

demo = gr.TabbedInterface([encrypt_interface, decrypt_interface], ["Encrypt", "Decrypt"])
demo.launch()

