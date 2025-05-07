import numpy as np
import nest_asyncio
import matplotlib.pyplot as plt
from scapy.all import *

nest_asyncio.apply()

# função pra pegar o ip do host fonte pro host destino
def get_ips(pkts):
    ip_src, ip_dest = pkts[0][IP].src, pkts[0][IP].dst
    return ip_src, ip_dest

# função para calcular o throughput médio
def calculate_throughput(pkts):
    total = sum(len(pkt) for pkt in pkts) # número total de bytes
    dur = pkts[-1].time - pkts[0].time  # duração da transmissão
    throughput = total/ dur # throughput médio
    return throughput

# função para calcular o tempo médio entre cada pacote
def interval_between_pkts(pkts):
    time_diff = np.diff([pkt.time for pkt in pkts])
    mean_interval = np.mean(time_diff.astype(float))
    return mean_interval

# função para contar a quantidade de pacotes ICMP
def count_icmp_pkts(pkts):
    tcp_pkts = [pkt for pkt in pkts if ICMP in pkt]
    return len(tcp_pkts)

# função que gera gráficos para uma captura
def generate_graphs(pkts, label):
    idx = np.arange(1, len(pkts) + 1)
    sizes = np.array([len(pkt) for pkt in pkts]) # tamanho dos pacotes
    times = np.array([pkt.time for pkt in pkts]) # tempo de chegada de cada pacotes
    intervals = np.diff(times) # diferença entre pacotes consecutivos

    # Throughput entre pacotes consecutivos 
    throughput = sizes[1:] / intervals

    # --- Gráficos ---
    fig, axes = plt.subplots(3, 1, figsize=(8, 12), tight_layout=True)

    # Tamanho x Pacote
    axes[0].plot(idx, sizes)
    axes[0].set_xlabel("Número do pacote")
    axes[0].set_ylabel("Tamanho (bytes)")
    axes[0].set_title("Tamanho vs. Pacote")
    axes[0].grid(True)

    # Throughput instantâneo x Pacote
    axes[1].plot(idx[1:], throughput, marker='o', linestyle='-')
    axes[1].set_xlabel("Número do pacote")
    axes[1].set_ylabel("Throughput instantâneo (bytes/s)")
    axes[1].set_title("Throughput por intervalo entre pacotes")
    axes[1].grid(True)

    # Intervalo de tempo x Pacote
    axes[2].plot(idx[1:], intervals)
    axes[2].set_xlabel("Número do pacote")
    axes[2].set_ylabel("Intervalo (s)")
    axes[2].set_title("Intervalo entre pacotes vs. Pacote")
    axes[2].grid(True)

    fig.savefig(f"graphs_{label}")
    plt.close(fig)

# função que, dada uma captura, devolve informações da conexão
def extract_infos(pcap_file, label):
    print(f"**** Extracting info from pcap file {pcap_file} ****")
    
    pkts = rdpcap(pcap_file) # lê os pacotes do arquivo .pcap

    total_tcp = count_icmp_pkts(pkts)
    ip_src, ip_dest = get_ips(pkts)
    throuput = calculate_throughput(pkts)
    mean_interval = interval_between_pkts(pkts)

    print("Total of icmp packets is: ", total_tcp)
    print(f"ip origem é: {ip_src}, ip destino é: {ip_dest}")
    print(f"Throughput médio é: {throuput:.4f} bytes/segundo")
    print(f"O tempo médio entre pacotes é: {mean_interval:.6f} segundos")
    generate_graphs(pkts, label)
    print()


if __name__ == "__main__":
    pcap_file_h1 = "../pcap-data/pcap-h1.pcap"
    pcap_file_h2 = "../pcap-data/pcap-h2.pcap"

    extract_infos(pcap_file_h1, "h1->h3")
    extract_infos(pcap_file_h2, "h2->h4")

