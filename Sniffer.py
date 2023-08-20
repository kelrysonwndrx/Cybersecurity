import socket
import struct

def main():

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind(('wlp1s0', 0x0800))
    
    raw_data = s.recv(2000)
    dest_mac, orig_mac, eth_proto, data = ethernet_frame(raw_data)
    print('\ndata: ', raw_data)
    print('\nCabecalho Ethernet')
    print('\nEnd Mac Destino: ', dest_mac)
    print('End Mac Origem: ', orig_mac)
    print('Tipo Protocolo: ', eth_proto)

    print('\nCabecalho IP')
    versao = raw_data[14] >> 4
    print('\nVersao: ', versao)

    IHL = raw_data[14] & 0b00001111
    print('Internet Header Length: ', IHL)

    typeOfService = raw_data[15]
    print('TypeOfService:', typeOfService)

    comprimento_total = raw_data[16]*(0b100000000) + raw_data[17]
    print('Compriment Total:', comprimento_total)

    id = raw_data[18]*(0b100000000) + raw_data[19]
    print('Identificacao: ', id)

    flags = (raw_data[20] & 0xe0) >> 5
    print('flagsIP: ', bin(flags))

    offsetFragmento = (raw_data[20] & 0b00011111)*0b100000000 + raw_data[21]

    print('Offset Fragmento: ', offsetFragmento)

    TTL = raw_data[22]
    print('TimeToLive: ', TTL)

    protocolo = raw_data[23]
    print('Protocolo: ', protocolo)

    print('Endereco de Origem: ', formatarEnderecoIp(
        struct.unpack('4s', raw_data[26:30])[0]))
    print('Endereco de Destino: ', formatarEnderecoIp(
        struct.unpack('4s', raw_data[30:34])[0]))

    if protocolo == 6:
        protocoloTCP(IHL, raw_data)
    elif protocolo == 17:
        protocoloUDP(IHL, raw_data)


def ethernet_frame(data):
    dest_mac, orig_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return formatarEnderecoMac(dest_mac), formatarEnderecoMac(orig_mac), socket.htons(proto), data[14:]


def formatarEnderecoMac(ip):
    ip = map('{:02x}'.format, ip)   # x para manter hexadecimal
    return ':'.join(ip)


def formatarEnderecoIp(ip):
    ip = map('{:01}'.format, ip)
    return '.'.join(ip)


def protocoloTCP(IHL, raw_data):
    print('\nProtocolo TCP\n')

    # Inicio do Protocolo de Transporte
    IPT = IHL*4
    
    portaOrigem = raw_data[IPT]*(0b100000000) + raw_data[IPT+1]
    print('Porta de Origem: ', portaOrigem, ('\n'))

    portaDeDestino = raw_data[IPT+2]*(0b100000000) + raw_data[IPT+3]
    print('Porta de Destino: ', portaDeDestino, ('\n'))

    seqNumb = socket.ntohl((raw_data[IPT+4]*0b1000000000000000000000000) + (raw_data[IPT+5]
                                                                            * 0b10000000000000000) + (raw_data[IPT+6]*0b100000000) + raw_data[IPT+7])

    print('Numero de Sequencia: ', seqNumb, ('\n'))

    ackNumb = socket.ntohl((raw_data[IPT+8]*0b1000000000000000000000000) + (raw_data[IPT+9]
                                                                            * 0b10000000000000000) + (raw_data[IPT+10]*0b100000000) + raw_data[IPT+11])

    print('Numero de ack: ', ackNumb, ('\n'))

    dataOffset = raw_data[IPT+12] & 0b11110000 >> 4
    print('DataOffset: ', dataOffset, ('\n'))

    Reservado = (raw_data[IPT+12] & 0x0f) << 2 + (raw_data[IPT+13] & 0x0f << 2)
    print('Reservado: ', Reservado, ('\n'))

    Urg = (raw_data[IPT+3] & 0b00100000) >> 5
    print('URG: ', Urg, ('\n'))

    ack = (raw_data[IPT+3] & 0b00010000) >> 4
    print('ACK: ', ack, ('\n'))

    psh = (raw_data[IPT+3] & 0b00001000) >> 3
    print('PSH: ', psh, ('\n'))

    pst = (raw_data[IPT+3] & 0b00000100) >> 2
    print('PST: ', pst, ('\n'))

    syn = (raw_data[IPT+3] & 0b00000010) >> 1
    print('SYN: ', syn, ('\n'))

    fin = (raw_data[IPT+3] & 0b0000001)
    print('FIN: ', fin, ('\n'))

    windowSize = raw_data[IPT+14]*(0b100000000) + raw_data[IPT+15]
    print('Tamanho da janela: ', windowSize, ('\n'))

    print('Dados:', raw_data[20:])
    
    return


def protocoloUDP(IHL, raw_data):
    print('\nProtocolo UDP\n')

    porta_origem = raw_data[IHL]*(0b100000000) + raw_data[IHL+1]
    print('Porta de Origem:', porta_origem)

    porta_destino = raw_data[IHL + 2]*(0b100000000) + raw_data[IHL+3]
    print('Porta de Destino:', porta_destino)

    comp = raw_data[IHL + 4]*(0b100000000) + raw_data[IHL+5]
    print('Comprimento:', comp)

    checksum = raw_data[IHL + 6]*(0b100000000) + raw_data[IHL+7]
    print('Checksum:', checksum)

    dados = raw_data[8:]

    print('Dados:', dados)

    return


main()
