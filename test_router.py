from router import parse_packet, create_packet

IP_packet_v1 = (
    bytes([127, 0, 0, 1])       # IP
    + (8885).to_bytes(2, "big") # puerto
    + bytes([10])               # TTL
    + (347).to_bytes(2, "big")  # ID
    + (0).to_bytes(2, "big")    # offset
    + (5).to_bytes(4, "big")    # tamaño
    + bytes([0])                # FLAG
    + b"hola!"                  # mensaje
)
parsed_IP_packet = parse_packet(IP_packet_v1)
IP_packet_v2 = create_packet(parsed_IP_packet)
print("IP_packet_v1 == IP_packet_v2 ? {}".format(IP_packet_v1 == IP_packet_v2))