#!pip install pillow cryptography stegano
!pip install stepic pillow cryptography

from PIL import Image
import stepic
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import hashlib

def menu():
    print("\nEscolha uma opção:")
    print("(1) Embutir texto em uma imagem usando Steganography")
    print("(2) Recuperar texto de uma imagem")
    print("(3) Gerar hash das imagens original e alterada")
    print("(4) Encriptar mensagem com chave pública e privada")
    print("(5) Decriptar mensagem com chave pública e privada")
    print("(S ou s) Sair")

def embed_text_in_image():
    image_path = input("Digite o caminho da imagem (formato PNG): ")
    message = input("Digite a mensagem a ser embutida: ")
    output_path = input("Digite o caminho para salvar a imagem alterada: ")

    # Abre a imagem e embute o texto
    image = Image.open(image_path)
    encoded_image = stepic.encode(image, message.encode())
    encoded_image.save(output_path, "PNG")
    print(f"Mensagem embutida e imagem salva em {output_path}")

def retrieve_text_from_image():
    image_path = input("Digite o caminho da imagem alterada (formato PNG): ")
    # Abre a imagem e recupera o texto embutido
    image = Image.open(image_path)
    message = stepic.decode(image)
    if message:
        print("Mensagem recuperada:", message)
    else:
        print("Nenhuma mensagem encontrada na imagem.")

def generate_image_hash():
    image_path = input("Digite o caminho da imagem: ")

    # Calcula o hash SHA-256 da imagem
    with open(image_path, "rb") as image_file:
        img_hash = hashlib.sha256(image_file.read()).hexdigest()
        print(f"Hash da imagem {image_path}: {img_hash}")

def encrypt_message():
    message = input("Digite a mensagem a ser encriptada: ").encode()

    # Gera chaves pública e privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Encripta a mensagem com a chave pública
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Converte a mensagem encriptada para base64 para facilitar a embutida
    encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
    print("Mensagem encriptada em base64:", encrypted_message_b64)
    
    # Salva as chaves para uso posterior
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    return encrypted_message_b64  # Retorna a mensagem codificada em base64

def embed_encrypted_message_in_image(encrypted_message_b64):
    image_path = input("Digite o caminho da imagem original (formato PNG): ")
    output_path = input("Digite o caminho para salvar a imagem alterada: ")

    # Abre a imagem e embute o texto encriptado (em base64)
    image = Image.open(image_path)
    encoded_image = stepic.encode(image, encrypted_message_b64.encode())
    encoded_image.save(output_path, "PNG")
    print(f"Imagem com mensagem encriptada salva em {output_path}")

def decrypt_message():
    image_path = input("Digite o caminho da imagem alterada (formato PNG): ")
    encrypted_message_b64 = stepic.decode(Image.open(image_path))

    # Decodifica de base64 para binário
    encrypted_message = base64.b64decode(encrypted_message_b64)

    # Carrega a chave privada para decriptar a mensagem
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    # Decripta a mensagem com a chave privada
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Mensagem decriptada:", decrypted_message.decode())

def main():
    while True:
        menu()
        option = input("Digite a opção desejada: ")

        if option == '1':
            embed_text_in_image()
        elif option == '2':
            retrieve_text_from_image()
        elif option == '3':
            generate_image_hash()
        elif option == '4':
            encrypted_message_b64 = encrypt_message()
            print("Embutindo mensagem encriptada na imagem...")
            embed_encrypted_message_in_image(encrypted_message_b64)
        elif option == '5':
            decrypt_message()
        elif option.lower() == 's':
            print("Saindo...")
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
