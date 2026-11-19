from router import fragment_IP_packet, reassemble_IP_packet

IP_packet_v1 = (
    bytes([127, 0, 0, 1]) + (8885).to_bytes(2, "big") + bytes([10])
    + (347).to_bytes(2, "big") + (0).to_bytes(2, "big")
    + (134).to_bytes(4, "big") + bytes([0])
    + b"A" * 134
)
fragment_list = fragment_IP_packet(IP_packet_v1, 100)
IP_packet_v2 = reassemble_IP_packet(fragment_list)
print("IP_packet_v1 = IP_packet_v2 ? {}".format(IP_packet_v1 == IP_packet_v2))

# Desordenado: debe seguir reensamblando
print("desordenado:", IP_packet_v1 == reassemble_IP_packet(fragment_list[::-1]))

# Incompleto: falta el último fragmento -> None
print("incompleto:", reassemble_IP_packet(fragment_list[:1]))

