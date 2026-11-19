import sys
import socket

# =============================================================================
# Constantes
# =============================================================================

# Tamaño fijo del header, en bytes:
# IP(4) + puerto(2) + TTL(1) + ID(2) + offset(2) + tamaño(4) + FLAG(1)
HEADER_SIZE = 16


# =============================================================================
# Parseo y construcción de paquetes
# =============================================================================

def parse_packet(IP_packet: bytes) -> dict:
    # Extrae los campos del header por posición de bytes y devuelve un dict.
    # El mensaje se devuelve como bytes (no str), porque un corte de fragmento
    # puede caer en medio de un carácter UTF-8.
    """Header de 16 bytes: IP(4) puerto(2) TTL(1) ID(2) offset(2) tamaño(4) FLAG(1)."""
    dest_ip = ".".join(str(b) for b in IP_packet[0:4])
    dest_port = int.from_bytes(IP_packet[4:6], byteorder="big")
    ttl = IP_packet[6]
    pid = int.from_bytes(IP_packet[7:9], byteorder="big")
    offset = int.from_bytes(IP_packet[9:11], byteorder="big")
    size = int.from_bytes(IP_packet[11:15], byteorder="big")
    flag = IP_packet[15]
    message = IP_packet[HEADER_SIZE:HEADER_SIZE + size]  # bytes, no str
    return {
        "ip": dest_ip, "port": dest_port, "ttl": ttl,
        "id": pid, "offset": offset, "size": size, "flag": flag,
        "msg": message,
    }

def create_packet(parsed_IP_packet: dict) -> bytes:
    # Operación inversa de parse_packet. El campo tamaño se recalcula desde
    # len(msg), así siempre coincide con el mensaje real.
    """Reconstruye los bytes del paquete (header de 16 bytes + mensaje)."""
    ip_bytes = bytes(int(p) for p in parsed_IP_packet["ip"].split("."))
    port_bytes = parsed_IP_packet["port"].to_bytes(2, byteorder="big")
    ttl_byte = bytes([parsed_IP_packet["ttl"]])
    id_bytes = parsed_IP_packet["id"].to_bytes(2, byteorder="big")
    offset_bytes = parsed_IP_packet["offset"].to_bytes(2, byteorder="big")
    size_bytes = len(parsed_IP_packet["msg"]).to_bytes(4, byteorder="big")
    flag_byte = bytes([parsed_IP_packet["flag"]])
    return (ip_bytes + port_bytes + ttl_byte + id_bytes
            + offset_bytes + size_bytes + flag_byte + parsed_IP_packet["msg"])


# =============================================================================
# Fragmentación
# =============================================================================

def fragment_IP_packet(IP_packet: bytes, MTU: int) -> list:
    # Divide el paquete en fragmentos de tamaño <= MTU. El MTU incluye el header,
    # así que cada trozo lleva MTU - HEADER_SIZE bytes de mensaje.
    # Devuelve siempre una lista con al menos un elemento.
    """Divide un paquete IP (bytes con header de 16) en fragmentos de tamaño <= MTU.
    Devuelve una lista con al menos un elemento."""
    # Caso 1: cabe en el enlace, no se fragmenta
    if len(IP_packet) <= MTU:
        return [IP_packet]

    parsed = parse_packet(IP_packet)
    msg = parsed["msg"]
    max_data = MTU - HEADER_SIZE
    if max_data <= 0:
        raise ValueError(f"MTU {MTU} demasiado pequeño")

    fragments = []
    total = len(msg)
    for start in range(0, total, max_data):
        chunk = msg[start:start + max_data]
        # El último trozo es el que alcanza el final del mensaje
        es_ultimo_trozo = (start + max_data) >= total
        frag = {
            "ip": parsed["ip"], "port": parsed["port"], "ttl": parsed["ttl"],
            "id": parsed["id"],
            # Offset relativo al datagrama original: offset de entrada + posición
            "offset": parsed["offset"] + start,
            "size": len(chunk),
            # Si el fragmento de entrada ya tenía FLAG 1, todo trozo también lo tiene
            "flag": 1 if (parsed["flag"] == 1 or not es_ultimo_trozo) else 0,
            "msg": chunk,
        }
        fragments.append(create_packet(frag))
    return fragments


# =============================================================================
# Reensamblado
# =============================================================================

def reassemble_IP_packet(fragment_list: list):
    # Reconstruye el datagrama a partir de sus fragmentos, sin importar el orden
    # de llegada. Devuelve los bytes del paquete completo o None si faltan trozos.
    """Reensambla un datagrama a partir de sus fragmentos (bytes con header de 16).
    Descarta duplicados por offset. Devuelve los bytes del paquete completo o None."""
    if not fragment_list:
        return None

    # Caso a): paquete sin fragmentar (FLAG 0, offset 0)
    if len(fragment_list) == 1:
        p = parse_packet(fragment_list[0])
        if p["flag"] == 0 and p["offset"] == 0:
            return fragment_list[0]
        return None  # b): un único fragmento incompleto

    parsed = [parse_packet(f) for f in fragment_list]

    # Descartar duplicados: un fragmento por offset (las copias llegan por rutas distintas)
    vistos = {}
    for p in parsed:
        vistos.setdefault(p["offset"], p)
    # Ordenar por offset
    parsed = [vistos[k] for k in sorted(vistos)]

    # Solo el último puede tener FLAG 0
    if parsed[-1]["flag"] != 0 or any(p["flag"] != 1 for p in parsed[:-1]):
        return None

    # Verificar contigüidad desde offset 0: cada offset debe igualar la suma previa
    expected = 0
    for p in parsed:
        if p["offset"] != expected:
            return None  # falta un fragmento
        expected += p["size"]

    # Concatenar mensajes y armar el paquete completo (offset 0, FLAG 0)
    message = b"".join(p["msg"] for p in parsed)
    base = parsed[0]
    full = {
        "ip": base["ip"], "port": base["port"], "ttl": base["ttl"],
        "id": base["id"], "offset": 0, "size": len(message), "flag": 0,
        "msg": message,
    }
    return create_packet(full)


# =============================================================================
# Enrutamiento
# =============================================================================

def check_routes(routes_file_name: str, destination_address: tuple, rr_state: dict):
    # Busca en la tabla las reglas que cubren el destino y alterna entre las de
    # la primera regla coincidente con round-robin. rr_state guarda el índice
    # de la última ruta usada por regla y debe persistir mientras corre el router.
    """Devuelve (next_hop, mtu) o None. Round-robin por regla.
    Acepta filas con 5 o 6 columnas: si no hay MTU, se asume None."""
    dest_ip, dest_port = destination_address
    matching_routes = []
    try:
        with open(routes_file_name, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                net_cidr = parts[0]
                port_ini, port_fin = int(parts[1]), int(parts[2])
                next_hop = (parts[3], int(parts[4]))
                mtu = int(parts[5]) if len(parts) >= 6 else None
                network_ip = net_cidr.split("/")[0]
                if dest_ip == network_ip and port_ini <= dest_port <= port_fin:
                    matching_routes.append(((net_cidr, port_ini, port_fin), next_hop, mtu))
    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo de rutas: {routes_file_name}")
        return None

    if not matching_routes:
        return None

    # Round-robin solo entre reglas idénticas a la primera coincidencia
    area_key = matching_routes[0][0]
    candidates = [(hop, mtu) for area, hop, mtu in matching_routes if area == area_key]
    idx = rr_state.get(area_key, 0) % len(candidates)
    rr_state[area_key] = (idx + 1) % len(candidates)
    return candidates[idx]  # (next_hop, mtu)


# =============================================================================
# Programa principal del router
# =============================================================================

def main():
    # Levanta el router en (IP, puerto) y procesa datagramas en un bucle.
    # Uso: python3 router.py router_IP router_puerto router_rutas.txt
    # Si el destino es este router, entrega (con buffer por ID). Si no, reenvía
    # descartando por TTL, consultando la tabla, fragmentando según el MTU de salida.
    """Punto de entrada del router."""
    if len(sys.argv) != 4:
        print("Uso correcto: python3 router.py router_IP router_puerto router_rutas.txt")
        sys.exit(1)

    router_ip = sys.argv[1]
    router_port = int(sys.argv[2])
    routes_file = sys.argv[3]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((router_ip, router_port))
    print(f"[LISTENING] {router_ip}:{router_port} (rutas: {routes_file})\n")

    current = (router_ip, router_port)
    rr_state = {}  # estado del round-robin, por regla de tabla

    try:
        buffers = {}  # fragmentos recibidos como destino final, indexados por ID
        while True:
            packet_bytes, _ = sock.recvfrom(4096)
            parsed = parse_packet(packet_bytes)
            dest = (parsed["ip"], parsed["port"])

            # Entrega local: el paquete es para este router
            if dest == current:
                lista = buffers.setdefault(parsed["id"], [])
                if packet_bytes not in lista:  # descarta copias exactas
                    lista.append(packet_bytes)
                full_packet = reassemble_IP_packet(lista)
                if full_packet is not None:
                    msg = parse_packet(full_packet)["msg"]
                    print(f"ID {parsed['id']} completo: {msg.decode('utf-8')[:20]}...")
                    del buffers[parsed["id"]]  # libera el buffer del ID
                else:
                    print(f"Esperando más fragmentos del ID {parsed['id']} ({len(lista)} recibido(s))")
                continue

            # Reenvío: el paquete es para otro destino
            if parsed["ttl"] <= 0:
                print(f"Se recibió paquete {packet_bytes} con TTL 0")
                continue

            result = check_routes(routes_file, dest, rr_state)
            if result is None:
                print(f"No hay rutas hacia {dest} para paquete {packet_bytes}")
                continue
            next_hop, mtu = result

            # Decrementar TTL antes de forwardear
            parsed["ttl"] -= 1
            new_packet = create_packet(parsed)

            # Fragmentar según el MTU del enlace de salida
            fragments = fragment_IP_packet(new_packet, mtu)
            print(f"redirigiendo paquete ({len(fragments)} fragmento(s)) con destino final {dest} desde {current} hacia {next_hop} (MTU {mtu})")
            for frag in fragments:
                sock.sendto(frag, next_hop)
    except KeyboardInterrupt:
        print("\n[EXIT] Deteniendo router...")
        sock.close()

if __name__ == "__main__":
    main()