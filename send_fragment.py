import sys, pickle, socket

modo = sys.argv[1]  # orden | desorden | intercalado
with open("fragmentos.pkl", "rb") as f:
    data = pickle.load(f)
A, B = data["A"], data["B"]

if modo == "orden":
    envio = A + B
elif modo == "desorden":
    envio = A[::-1] + B[::-1]
elif modo == "intercalado":
    envio = [A[0], B[0], A[1], B[1]]
else:
    sys.exit("Modo: orden | desorden | intercalado")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for pkt in envio:
    sock.sendto(pkt, ("127.0.0.1", 8885))  # primer salto: R1
sock.close()
print(f"Enviados {len(envio)} fragmentos en modo {modo}")