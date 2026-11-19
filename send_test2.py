import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
mensaje = b"X" * 134  # 16 + 134 = 150 bytes totales

for i in range(3):
    paquete = (bytes([127, 0, 0, 1]) + (8885).to_bytes(2, "big") + bytes([10])
               + (901 + i).to_bytes(2, "big") + (0).to_bytes(2, "big")
               + (134).to_bytes(4, "big") + bytes([0]) + mensaje)
    s.sendto(paquete, ("127.0.0.1", 8881))  # primer salto: R1

s.close()
print("Enviados 3 paquetes de 150 bytes (IDs 901, 902, 903)")