#!/bin/bash

function configure_openvpn_client {
    echo "Digite o caminho dos arquivos de configuração do cliente OpenVPN (ovpn, crt, key, ca):"
    read CONFIG_PATH

    if [ ! -d "$CONFIG_PATH" ]; then
        echo "Caminho não encontrado. Por favor, verifique e tente novamente."
        exit 1
    fi

    CONFIG_FILE=$(find $CONFIG_PATH -name "*.ovpn" | head -n 1)
    CA_FILE=$(find $CONFIG_PATH -name "ca.crt" | head -n 1)
    CERT_FILE=$(find $CONFIG_PATH -name "*.crt" | grep -v "ca.crt" | head -n 1)
    KEY_FILE=$(find $CONFIG_PATH -name "*.key" | head -n 1)

    if [ -z "$CONFIG_FILE" ] || [ -z "$CA_FILE" ] || [ -z "$CERT_FILE" ] || [ -z "$KEY_FILE" ]; then
        echo "Arquivos de configuração não encontrados. Por favor, verifique e tente novamente."
        exit 1
    fi

    echo "Arquivos de configuração encontrados:"
    echo "Configuração (.ovpn): $CONFIG_FILE"
    echo "CA (.crt): $CA_FILE"
    echo "Certificado (.crt): $CERT_FILE"
    echo "Chave (.key): $KEY_FILE"

    echo "Configurando o cliente OpenVPN..."
    cp $CONFIG_FILE /etc/openvpn/client.conf
    cp $CA_FILE /etc/openvpn/ca.crt
    cp $CERT_FILE /etc/openvpn/client.crt
    cp $KEY_FILE /etc/openvpn/client.key

    sed -i 's|ca ca.crt|ca /etc/openvpn/ca.crt|' /etc/openvpn/client.conf
    sed -i 's|cert client.crt|cert /etc/openvpn/client.crt|' /etc/openvpn/client.conf
    sed -i 's|key client.key|key /etc/openvpn/client.key|' /etc/openvpn/client.conf

    echo "Configuração do cliente OpenVPN concluída."
}

function connect_openvpn {
    echo "Conectando ao servidor OpenVPN..."
    sudo openvpn --config /etc/openvpn/client.conf &
    echo "Cliente conectado."
}

function disconnect_openvpn {
    echo "Desconectando do servidor OpenVPN..."
    pkill openvpn
    echo "Cliente desconectado."
}

function configure_wireguard_client {
    echo "Digite o caminho do arquivo de configuração do cliente WireGuard (wg0.conf):"
    read CONFIG_PATH

    if [ ! -f "$CONFIG_PATH/wg0.conf" ]; then
        echo "Arquivo de configuração wg0.conf não encontrado no caminho especificado. Por favor, verifique e tente novamente."
        exit 1
    fi

    echo "Arquivo de configuração encontrado: $CONFIG_PATH/wg0.conf"

    echo "Configurando o cliente WireGuard..."
    cp $CONFIG_PATH/wg0.conf /etc/wireguard/wg0.conf

    echo "Configuração do cliente WireGuard concluída."
}

function connect_wireguard {
    echo "Conectando ao servidor WireGuard..."
    sudo wg-quick up wg0
    echo "Cliente conectado."
}

function disconnect_wireguard {
    echo "Desconectando do servidor WireGuard..."
    sudo wg-quick down wg0
    echo "Cliente desconectado."
}

function create_route {
    echo "Digite o IP da rede cliente do servidor (ex. 10.8.0.0/24):"
    read CLIENT_NETWORK
    echo "Digite o IP do gateway (ex. 192.168.1.1):"
    read GATEWAY

    sudo ip route add $CLIENT_NETWORK via $GATEWAY
    if [ $? -eq 0 ]; then
        echo "Rota adicionada: $CLIENT_NETWORK via $GATEWAY"
    else
        echo "Erro ao adicionar a rota: $CLIENT_NETWORK via $GATEWAY"
    fi
}

function delete_firewall_rules {
    echo "Excluindo regras de firewall..."

    # Remover regras de firewall para OpenVPN
    iptables -D FORWARD -i tun0 -o eth0 -j ACCEPT
    iptables -D FORWARD -i eth0 -o tun0 -j ACCEPT
    iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

    # Remover regras de firewall para WireGuard
    iptables -D FORWARD -i wg0 -o eth0 -j ACCEPT
    iptables -D FORWARD -i eth0 -o wg0 -j ACCEPT
    iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE

    iptables-save > /etc/iptables/rules.v4

    echo "Regras de firewall excluídas."
}

echo "Escolha o tipo de VPN:"
echo "1) OpenVPN"
echo "2) WireGuard"

read VPN_CHOICE

if [ $VPN_CHOICE -eq 1 ]; then
    echo "Escolha uma opção:"
    echo "1) Configurar cliente OpenVPN"
    echo "2) Conectar ao servidor OpenVPN"
    echo "3) Desconectar do servidor OpenVPN"
    echo "4) Criar regras de rota"
    echo "5) Excluir regras de firewall"

    read OPTION

    case $OPTION in
        1)
            configure_openvpn_client
            ;;
        2)
            connect_openvpn
            ;;
        3)
            disconnect_openvpn
            ;;
        4)
            create_route
            ;;
        5)
            delete_firewall_rules
            ;;
        *)
            echo "Opção inválida!"
            ;;
    esac
elif [ $VPN_CHOICE -eq 2 ]; then
    echo "Escolha uma opção:"
    echo "1) Configurar cliente WireGuard"
    echo "2) Conectar ao servidor WireGuard"
    echo "3) Desconectar do servidor WireGuard"
    echo "4) Criar regras de rota"
    echo "5) Excluir regras de firewall"

    read OPTION

    case $OPTION in
        1)
            configure_wireguard_client
            ;;
        2)
            connect_wireguard
            ;;
        3)
            disconnect_wireguard
            ;;
        4)
            create_route
            ;;
        5)
            delete_firewall_rules
            ;;
        *)
            echo "Opção inválida!"
            ;;
    esac
else
    echo "Escolha inválida!"
fi
