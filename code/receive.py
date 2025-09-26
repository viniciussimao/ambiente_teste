#!/usr/bin/env python3
import argparse
import sys
import socket
import struct
from scapy.all import Packet, bind_layers, BitField, ShortField, IntField, LongField, PacketListField, Ether, IP, sniff, ByteField

# Define o novo cabeçalho HostINT
class HostINT(Packet):
    name = "HostINT"
    fields_desc = [
        BitField("cpu_usage", 0, 32),        # Porcentagem de uso de CPU
        BitField("mem_usage", 0, 32),        # Porcentagem de uso de memória
        BitField("timestamp", 0, 48),        # Timestamp (48 bits)
        BitField("bind", 253, 8)             # Campo proto para indicar o próximo protocolo
    ]

class InBandNetworkTelemetry(Packet):
    fields_desc = [ BitField("switchID_t", 0, 31),
                    BitField("ingress_port", 0, 9),
                    BitField("egress_port", 0, 9),
                    BitField("egress_spec", 0, 9),
                    BitField("ingress_global_timestamp", 0, 48),
                    BitField("egress_global_timestamp", 0, 48),
                    BitField("enq_timestamp", 0, 32),
                    BitField("enq_qdepth", 0, 19),
                    BitField("deq_timedelta", 0, 32),
                    BitField("deq_qdepth", 0, 19)
                  ]

    def extract_padding(self, p):
        return "", p

class nodeCount(Packet):
    name = "nodeCount"
    fields_desc = [
        ShortField("count", 0),
        PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt: (pkt.count * 1))
    ]

def handle_pkt(pkt):
    # Verifica se o arquivo já possui cabeçalho, caso não tenha, adiciona.
    with open("dados_recebidos.txt", "a") as f:
        if f.tell() == 0:  # Verifica se o arquivo está vazio
            f.write("cpu_usage, mem_usage, timestamp, ")
            f.write("switchID_t_3, ingress_port_3, egress_port_3, egress_spec_3, ingress_global_timestamp_3, egress_global_timestamp_3, enq_timestamp_3, enq_qdepth_3, deq_timedelta_3, deq_qdepth_3, ")
            f.write("switchID_t_2, ingress_port_2, egress_port_2, egress_spec_2, ingress_global_timestamp_2, egress_global_timestamp_2, enq_timestamp_2, enq_qdepth_2, deq_timedelta_2, deq_qdepth_2, ")
            f.write("switchID_t_1, ingress_port_1, egress_port_1, egress_spec_1, ingress_global_timestamp_1, egress_global_timestamp_1, enq_timestamp_1, enq_qdepth_1, deq_timedelta_1, deq_qdepth_1\n")


        # Extraindo os dados do cabeçalho HostINT
        cpu_usage = pkt[HostINT].cpu_usage
        mem_usage = pkt[HostINT].mem_usage
        timestamp = pkt[HostINT].timestamp

        # String para armazenar os dados de cada pacote
        linha = f"{cpu_usage}, {mem_usage}, {timestamp}"

        # Verifica se o pacote contém o nodeCount e os dados INT
        if nodeCount in pkt:
            int_data = pkt[nodeCount].INT
            # Verifica o número de switches e coleta os dados
            for idx, int_entry in enumerate(int_data, 1):  # idx começa em 1 para representar o switch 1, 2, etc.
                switchID_t = int_entry.switchID_t
                ingress_port = int_entry.ingress_port
                egress_port = int_entry.egress_port
                egress_spec = int_entry.egress_spec
                ingress_global_timestamp = int_entry.ingress_global_timestamp
                egress_global_timestamp = int_entry.egress_global_timestamp
                enq_timestamp = int_entry.enq_timestamp
                enq_qdepth = int_entry.enq_qdepth
                deq_timedelta = int_entry.deq_timedelta
                deq_qdepth = int_entry.deq_qdepth

                # Adiciona os dados do switch na mesma linha
                linha += f", {switchID_t}, {ingress_port}, {egress_port}, {egress_spec}, {ingress_global_timestamp}, {egress_global_timestamp}, {enq_timestamp}, {enq_qdepth}, {deq_timedelta}, {deq_qdepth}"

            # Se houver menos de 3 switches, preenche com valores vazios
            if len(int_data) < 3:
                linha += ", " * (10 * (3 - len(int_data)))

        # Escreve a linha completa no arquivo
        f.write(linha + "\n")

def main():
    iface = 'enp0s8'
    
    # Vincula a camada HostINT ao protocolo 254
    bind_layers(IP, HostINT, proto=254)
    
    # Vincula a camada nodeCount ao protocolo 253 (INT)
    bind_layers(HostINT, nodeCount)
    
    # Inicia a captura de pacotes na interface especificada
    sniff(filter="ip proto 254", iface=iface, prn=lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
