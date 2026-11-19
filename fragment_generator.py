import pickle
from router import fragment_IP_packet

def paquete(id_, texto):
    msg = texto.encode("utf-8")
    return (bytes([127, 0, 0, 1]) + (8885).to_bytes(2, "big") + bytes([10])
            + id_.to_bytes(2, "big") + (0).to_bytes(2, "big")
            + len(msg).to_bytes(4, "big") + bytes([0]) + msg)

lista_a = fragment_IP_packet(paquete(111, "A" * 134), 100)
lista_b = fragment_IP_packet(paquete(222, "B" * 134), 100)

with open("fragmentos.pkl", "wb") as f:
    pickle.dump({"A": lista_a, "B": lista_b}, f)
print("A:", len(lista_a), "fragmentos | B:", len(lista_b), "fragmentos")