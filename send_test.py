import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
paquete = (bytes([127, 0, 0, 1]) + (8885).to_bytes(2, "big") + bytes([10])
           + (347).to_bytes(2, "big") + (0).to_bytes(2, "big")
           + (5).to_bytes(4, "big") + bytes([0]) + b"hola!")
for _ in range(4):
    s.sendto(paquete, ("127.0.0.1", 8881))
s.close()
print("Enviados 4 paquetes")