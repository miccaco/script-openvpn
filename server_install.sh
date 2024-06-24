#!/bin/bash

INSTALL_LOG="/arqs/clients/install_details.txt"
BACKUP_DIR="/arqs/backup"
CLIENTS_DIR="/arqs/clients"

function install_openvpn {
    echo "Atualizando repositórios..."
    apt update
    echo "Instalando OpenVPN e Easy-RSA..."
    apt install -y openvpn easy-rsa

    echo "Configurando Easy-RSA..."
    make-cadir ~/openvpn-ca
    cd ~/openvpn-ca
    ./easyrsa init-pki
    ./easyrsa build-ca nopass

    echo "Gerando chaves do servidor..."
    ./easyrsa gen-req server nopass
    ./easyrsa sign-req server server

    echo "Gerando Diffie-Hellman..."
    ./easyrsa gen-dh

    echo "Configurando servidor OpenVPN..."
    cd /etc/openvpn
    cp ~/openvpn-ca/pki/private/server.key server.key
    cp ~/openvpn-ca/pki/issued/server.crt server.crt
    cp ~/openvpn-ca/pki/ca.crt ca.crt
    cp ~/openvpn-ca/pki/dh.pem dh.pem

    echo "Copiando arquivo de configuração do servidor..."
    gunzip -c /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz > /etc/openvpn/server.conf

    echo "Alterando configurações do servidor..."
    sed -i 's/;tls-auth ta.key 0/tls-auth ta.key 0/' /etc/openvpn/server.conf
    sed -i 's/;cipher AES-256-CBC/cipher AES-256-GCM/' /etc/openvpn/server.conf
    echo "tls-crypt ta.key" >> /etc/openvpn/server.conf
    echo "dev tun" >> /etc/openvpn/server.conf

    echo "Gerando chaves tls-crypt..."
    openvpn --genkey --secret /etc/openvpn/ta.key

    echo "Habilitando encaminhamento de IP..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

    echo "Adicionando arquivo de status..."
    echo "status /var/log/openvpn-status.log" >> /etc/openvpn/server.conf

    echo "Configurando regras de firewall..."
    iptables -A FORWARD -i tun0 -o ens18 -j ACCEPT
    iptables -A FORWARD -i ens18 -o tun0 -j ACCEPT
#    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
    iptables-save > /etc/iptables/rules.v4

    echo "Reiniciando e habilitando OpenVPN..."
    systemctl restart openvpn@server
    systemctl enable openvpn@server

    echo "Servidor OpenVPN configurado com sucesso!"

    echo "Detalhes da Instalação do OpenVPN:" > $INSTALL_LOG
    echo "Porta: 1194" >> $INSTALL_LOG
    echo "Configurações do servidor: /etc/openvpn/server.conf" >> $INSTALL_LOG
    echo "Certificados e chaves: /etc/openvpn/" >> $INSTALL_LOG
}

function create_client_openvpn {
    echo "Entre com o nome do cliente:"
    read CLIENT_NAME

    cd ~/openvpn-ca
    ./easyrsa gen-req $CLIENT_NAME nopass
    ./easyrsa sign-req client $CLIENT_NAME

    CLIENT_DIR="$CLIENTS_DIR/$CLIENT_NAME"
    mkdir -p $CLIENT_DIR
    chmod 700 $CLIENT_DIR

    echo "Gerando arquivo de configuração do cliente..."
    cp pki/private/$CLIENT_NAME.key $CLIENT_DIR/
    cp pki/issued/$CLIENT_NAME.crt $CLIENT_DIR/
    cp pki/ca.crt $CLIENT_DIR/

    cat > $CLIENT_DIR/$CLIENT_NAME.ovpn <<EOF
client
dev tun
proto udp
remote YOUR_SERVER_IP 1194
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
ca ca.crt
cert $CLIENT_NAME.crt
key $CLIENT_NAME.key
tls-crypt ta.key
cipher AES-256-GCM
auth SHA256
verb 3
EOF

    echo "Copiando chaves tls-crypt para o cliente..."
    cp /etc/openvpn/ta.key $CLIENT_DIR/

    cat > $CLIENT_DIR/$CLIENT_NAME-readme.txt <<EOF
Passos para configurar o cliente OpenVPN:

1. Transfira os seguintes arquivos para o dispositivo cliente:
   - $CLIENT_NAME.ovpn
   - ca.crt
   - $CLIENT_NAME.crt
   - $CLIENT_NAME.key
   - ta.key

2. Instale o OpenVPN no dispositivo cliente:
   - No Windows, baixe e instale o OpenVPN GUI (https://openvpn.net/community-downloads/).
   - No Linux, instale o OpenVPN usando o gerenciador de pacotes (ex. apt install openvpn).

3. Importe o arquivo de configuração:
   - No Windows, coloque o arquivo $CLIENT_NAME.ovpn na pasta de configuração do OpenVPN (geralmente C:\\Program Files\\OpenVPN\\config) e inicie o OpenVPN GUI.
   - No Linux, use o comando: sudo openvpn --config /caminho/para/$CLIENT_NAME.ovpn

4. Conecte ao servidor:
   - No Windows, abra o OpenVPN GUI, clique com o botão direito no ícone do OpenVPN na bandeja do sistema, selecione o perfil do cliente e clique em "Conectar".
   - No Linux, o comando acima já conectará ao servidor.

EOF

    echo "Cliente $CLIENT_NAME criado com sucesso! Arquivo de configuração: $CLIENT_DIR/$CLIENT_NAME.ovpn"

    echo "Cliente $CLIENT_NAME:" >> $INSTALL_LOG
    echo "Configuração do cliente: $CLIENT_DIR/$CLIENT_NAME.ovpn" >> $INSTALL_LOG
    echo "Chave privada: $CLIENT_DIR/$CLIENT_NAME.key" >> $INSTALL_LOG
    echo "Certificado: $CLIENT_DIR/$CLIENT_NAME.crt" >> $INSTALL_LOG
    echo "CA: $CLIENT_DIR/ca.crt" >> $INSTALL_LOG
    echo "Chave TLS-Crypt: $CLIENT_DIR/ta.key" >> $INSTALL_LOG
}

function delete_client_openvpn {
    echo "Entre com o nome do cliente para excluir:"
    read CLIENT_NAME

    CLIENT_DIR="$CLIENTS_DIR/$CLIENT_NAME"
    if [ -d "$CLIENT_DIR" ]; then
        rm -rf "$CLIENT_DIR"
        echo "Cliente $CLIENT_NAME e seus dados foram excluídos com sucesso!"
    else
        echo "Cliente $CLIENT_NAME não encontrado!"
    fi
}

function modify_port_openvpn {
    echo "Entre com a nova porta para o OpenVPN:"
    read NEW_PORT

    sed -i "s/port [0-9]*/port $NEW_PORT/" /etc/openvpn/server.conf
    systemctl restart openvpn@server
    echo "Porta modificada para $NEW_PORT e serviço reiniciado."
    echo "Porta modificada para: $NEW_PORT" >> $INSTALL_LOG
}

function restart_service_openvpn {
    systemctl restart openvpn@server
    echo "Serviço OpenVPN reiniciado."
}

function uninstall_openvpn {
    echo "Desinstalando OpenVPN e removendo todos os arquivos de configuração..."
    systemctl stop openvpn@server
    systemctl disable openvpn@server
    apt remove --purge -y openvpn easy-rsa
    rm -rf /etc/openvpn
    rm -rf ~/openvpn-ca
    rm -rf $CLIENTS_DIR
    rm -f $INSTALL_LOG
    echo "OpenVPN desinstalado e todos os arquivos removidos."
}

function backup_configs {
    echo "Entre com o caminho para salvar o backup:"
    read BACKUP_PATH

    mkdir -p $BACKUP_DIR
    tar -czf "$BACKUP_PATH/openvpn_backup_$(date +%F).tar.gz" /etc/openvpn ~/openvpn-ca $CLIENTS_DIR $INSTALL_LOG
    echo "Backup criado em $BACKUP_PATH/openvpn_backup_$(date +%F).tar.gz"
}

function restore_configs {
    echo "Entre com o caminho do arquivo de backup:"
    read BACKUP_FILE

    if [ -f "$BACKUP_FILE" ]; then
        tar -xzf "$BACKUP_FILE" -C /
        systemctl restart openvpn@server
        echo "Backup restaurado e serviço OpenVPN reiniciado."
    else
        echo "Arquivo de backup não encontrado!"
    fi
}

function install_wireguard {
    echo "Atualizando repositórios..."
    apt update
    echo "Instalando WireGuard..."
    apt install -y wireguard

    echo "Configurando WireGuard..."
    mkdir -p /etc/wireguard
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key

    SERVER_PRIVATE_KEY=$(cat /etc/wireguard/server_private.key)

    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIVATE_KEY
SaveConfig = true
EOF

    echo "Habilitando encaminhamento de IP..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

    echo "Configurando regras de firewall..."
    iptables -A FORWARD -i wg0 -o ens18 -j ACCEPT
    iptables -A FORWARD -i ens18 -o wg0 -j ACCEPT
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables-save > /etc/iptables/rules.v4

    echo "Iniciando e habilitando WireGuard..."
    systemctl start wg-quick@wg0
    systemctl enable wg-quick@wg0

    echo "Servidor WireGuard configurado com sucesso!"

    echo "Detalhes da Instalação do WireGuard:" > $INSTALL_LOG
    echo "Porta: 51820" >> $INSTALL_LOG
    echo "Configurações do servidor: /etc/wireguard/wg0.conf" >> $INSTALL_LOG
    echo "Chaves: /etc/wireguard/" >> $INSTALL_LOG
}

function create_client_wireguard {
    echo "Entre com o nome do cliente:"
    read CLIENT_NAME

    CLIENT_DIR="$CLIENTS_DIR/$CLIENT_NAME"
    mkdir -p $CLIENT_DIR
    chmod 700 $CLIENT_DIR

    wg genkey | tee $CLIENT_DIR/private.key | wg pubkey > $CLIENT_DIR/public.key
    CLIENT_PRIVATE_KEY=$(cat $CLIENT_DIR/private.key)
    CLIENT_PUBLIC_KEY=$(cat $CLIENT_DIR/public.key)
    SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)

    cat > $CLIENT_DIR/$CLIENT_NAME.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.0.0.2/24

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = YOUR_SERVER_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 21
EOF

    cat > $CLIENT_DIR/$CLIENT_NAME-readme.txt <<EOF
Passos para configurar o cliente WireGuard:

1. Transfira os seguintes arquivos para o dispositivo cliente:
   - $CLIENT_NAME.conf

2. Instale o WireGuard no dispositivo cliente:
   - No Windows, baixe e instale o WireGuard (https://www.wireguard.com/install/).
   - No Linux, instale o WireGuard usando o gerenciador de pacotes (ex. apt install wireguard).

3. Importe o arquivo de configuração:
   - No Windows, abra o aplicativo WireGuard, clique em "Import tunnel(s) from file", selecione o arquivo $CLIENT_NAME.conf.
   - No Linux, use o comando: sudo wg-quick up /caminho/para/$CLIENT_NAME.conf

4. Conecte ao servidor:
   - No Windows, clique em "Activate" no aplicativo WireGuard.
   - No Linux, o comando acima já conectará ao servidor.

EOF

    echo "Cliente $CLIENT_NAME criado com sucesso! Arquivo de configuração: $CLIENT_DIR/$CLIENT_NAME.conf"

    echo "Cliente $CLIENT_NAME:" >> $INSTALL_LOG
    echo "Configuração do cliente: $CLIENT_DIR/$CLIENT_NAME.conf" >> $INSTALL_LOG
    echo "Chave privada: $CLIENT_DIR/private.key" >> $INSTALL_LOG
    echo "Chave pública: $CLIENT_DIR/public.key" >> $INSTALL_LOG
}

function delete_client_wireguard {
    echo "Entre com o nome do cliente para excluir:"
    read CLIENT_NAME

    CLIENT_DIR="$CLIENTS_DIR/$CLIENT_NAME"
    if [ -d "$CLIENT_DIR" ]; then
        rm -rf "$CLIENT_DIR"
        echo "Cliente $CLIENT_NAME e seus dados foram excluídos com sucesso!"
    else
        echo "Cliente $CLIENT_NAME não encontrado!"
    fi
}

function modify_port_wireguard {
    echo "Entre com a nova porta para o WireGuard:"
    read NEW_PORT

    sed -i "s/ListenPort = [0-9]*/ListenPort = $NEW_PORT/" /etc/wireguard/wg0.conf
    systemctl restart wg-quick@wg0
    echo "Porta modificada para $NEW_PORT e serviço reiniciado."
    echo "Porta modificada para: $NEW_PORT" >> $INSTALL_LOG
}

function restart_service_wireguard {
    systemctl restart wg-quick@wg0
    echo "Serviço WireGuard reiniciado."
}

function uninstall_wireguard {
    echo "Desinstalando WireGuard e removendo todos os arquivos de configuração..."
    systemctl stop wg-quick@wg0
    systemctl disable wg-quick@wg0
    apt remove --purge -y wireguard
    rm -rf /etc/wireguard
    rm -rf $CLIENTS_DIR
    rm -f $INSTALL_LOG
    echo "WireGuard desinstalado e todos os arquivos removidos."
}

function backup_configs_wireguard {
    echo "Entre com o caminho para salvar o backup:"
    read BACKUP_PATH

    mkdir -p $BACKUP_DIR
    tar -czf "$BACKUP_PATH/wireguard_backup_$(date +%F).tar.gz" /etc/wireguard $CLIENTS_DIR $INSTALL_LOG
    echo "Backup criado em $BACKUP_PATH/wireguard_backup_$(date +%F).tar.gz"
}

function restore_configs_wireguard {
    echo "Entre com o caminho do arquivo de backup:"
    read BACKUP_FILE

    if [ -f "$BACKUP_FILE" ]; then
        tar -xzf "$BACKUP_FILE" -C /
        systemctl restart wg-quick@wg0
        echo "Backup restaurado e serviço WireGuard reiniciado."
    else
        echo "Arquivo de backup não encontrado!"
    fi
}

function setup_firewall {
    echo "Configurando regras de firewall para permitir acesso à rede local..."
    echo "Entre com o IP da rede local (ex. 192.168.1.0/24):"
    read LOCAL_NETWORK

    # OpenVPN
    if [ -f /etc/openvpn/server.conf ]; then
#        iptables -D FORWARD -i tun0 -o ens18 -j ACCEPT
#        iptables -D FORWARD -i ens18 -o tun0 -j ACCEPT
        iptables -A FORWARD -i tun0 -o eth0 -s 10.8.0.0/24 -d $LOCAL_NETWORK -m conntrack --ctstate NEW -j ACCEPT
        iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens18 -j MASQUERADE

        # Salvando regras do iptables para OpenVPN
        iptables-save > /etc/iptables/rules.v4

        echo "iptables-restore < /etc/iptables/rules.v4" >> /etc/rc.local
    fi

    # WireGuard
    if [ -f /etc/wireguard/wg0.conf ]; then
        iptables -A FORWARD -i wg0 -o ens18 -s 10.0.0.0/24 -d $LOCAL_NETWORK -m conntrack --ctstate NEW -j ACCEPT
        iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o ens18 -j MASQUERADE

        # Salvando regras do iptables para WireGuard
        iptables-save > /etc/iptables/rules.v4

        echo "iptables-restore < /etc/iptables/rules.v4" >> /etc/rc.local
    fi

    echo "Regras de firewall configuradas com sucesso!"
}

function list_connected_clients {
    echo "Escolha o serviço VPN para listar os clientes conectados:"
    echo "1) OpenVPN"
    echo "2) WireGuard"

    read VPN_CHOICE

    if [ $VPN_CHOICE -eq 1 ]; then
        echo "Clientes conectados ao OpenVPN:"
        cat /var/log/openvpn-status.log
    elif [ $VPN_CHOICE -eq 2 ]; then
        echo "Clientes conectados ao WireGuard:"
        wg show
    else
        echo "Escolha inválida!"
    fi
}

echo "Escolha um serviço VPN para instalar:"
echo "1) OpenVPN"
echo "2) WireGuard"

read VPN_CHOICE

if [ $VPN_CHOICE -eq 1 ]; then
    echo "Escolha uma opção:"
    echo "1) Instalação completa do OpenVPN"
    echo "2) Criar cliente OpenVPN"
    echo "3) Excluir cliente OpenVPN"
    echo "4) Modificar porta do OpenVPN"
    echo "5) Reiniciar serviço OpenVPN"
    echo "6) Desinstalar e apagar tudo"
    echo "7) Fazer backup das configurações"
    echo "8) Restaurar a partir de um backup"
    echo "9) Configurar regras de firewall para acesso à rede local"
    echo "10) Listar clientes conectados"

    read OPTION

    case $OPTION in
        1)
            install_openvpn
            ;;
        2)
            create_client_openvpn
            ;;
        3)
            delete_client_openvpn
            ;;
        4)
            modify_port_openvpn
            ;;
        5)
            restart_service_openvpn
            ;;
        6)
            uninstall_openvpn
            ;;
        7)
            backup_configs
            ;;
        8)
            restore_configs
            ;;
        9)
            setup_firewall
            ;;
        10)
            list_connected_clients
            ;;
        *)
            echo "Opção inválida!"
            ;;
    esac
elif [ $VPN_CHOICE -eq 2 ]; then
    echo "Escolha uma opção:"
    echo "1) Instalação completa do WireGuard"
    echo "2) Criar cliente WireGuard"
    echo "3) Excluir cliente WireGuard"
    echo "4) Modificar porta do WireGuard"
    echo "5) Reiniciar serviço WireGuard"
    echo "6) Desinstalar e apagar tudo"
    echo "7) Fazer backup das configurações"
    echo "8) Restaurar a partir de um backup"
    echo "9) Configurar regras de firewall para acesso à rede local"
    echo "10) Listar clientes conectados"

    read OPTION

    case $OPTION in
        1)
            install_wireguard
            ;;
        2)
            create_client_wireguard
            ;;
        3)
            delete_client_wireguard
            ;;
        4)
            modify_port_wireguard
            ;;
        5)
            restart_service_wireguard
            ;;
        6)
            uninstall_wireguard
            ;;
        7)
            backup_configs_wireguard
            ;;
        8)
            restore_configs_wireguard
            ;;
        9)
            setup_firewall
            ;;
        10)
            list_connected_clients
            ;;
        *)
            echo "Opção inválida!"
            ;;
    esac
else
    echo "Escolha inválida!"
fi
