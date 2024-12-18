
# Documentação - Izanagi Hacking Wi-Fi Tool

## Introdução
Izanagi é uma ferramenta desenvolvida para realizar ataques de redes Wi-Fi e monitoramento de tráfego. 
Esta documentação detalha as funcionalidades de cada módulo e fornece orientações para seu uso.

## Bibliotecas Utilizadas
- `os`: Interação com o sistema operacional.
- `time`: Manipulação de atrasos e intervalos de tempo.
- `scapy.all`: Para criação e manipulação de pacotes de rede.
- `subprocess`: Execução de comandos externos no terminal.
- `colorama`: Fornece suporte para texto colorido no terminal.
- `random`: Geração de valores aleatórios.
- `threading`: Gerenciamento de threads.

## Funcionalidades
### 1. **Banner Inicial**
- Exibe um banner estilizado na inicialização da ferramenta.

### 2. **Captura de Handshake WPA**
- Identifica pacotes EAPOL (indispensáveis para ataques WPA).
- Salva os handshakes capturados em um arquivo `handshake.cap`.

### 3. **Ataque de Desautenticação**
- Envia pacotes de desautenticação para desconectar dispositivos de um ponto de acesso.

### 4. **Sniffer de Rede**
- Captura pacotes em uma interface de rede especificada.
- Identifica redes Wi-Fi disponíveis e exibe SSID, MAC, canal e tipo de criptografia.

### 5. **Ataque WPA**
- Realiza ataques de força bruta para descobrir senhas WPA/WPA2 com base em um arquivo de dicionário.

### 6. **ARP Spoofing**
- Executa ARP Spoofing para redirecionar tráfego entre dispositivos.

### 7. **Monitoramento de Tráfego**
- Monitora pacotes de uma interface de rede em tempo real.

### 8. **Ataque DoS**
- Envia pacotes ICMP para sobrecarregar um dispositivo alvo.

### 9. **Verificação de Dispositivos Conectados**
- Lista os dispositivos conectados à rede utilizando o comando `arp-scan`.

## Estrutura do Código
- **Funções Principais:**
  - `show_banner()`: Exibe o banner inicial.
  - `packet_callback_handshake(packet)`: Identifica e salva handshakes WPA.
  - `deauth_attack(target_mac, ap_mac, iface)`: Executa ataques de desautenticação.
  - `sniff_wifi(interface)`: Captura pacotes da interface especificada.
  - `wpa_attack(handshake_file, wordlist_file)`: Executa força bruta em redes WPA.
  - `arp_spoof(target_ip, gateway_ip, iface)`: Realiza ARP Spoofing.
  - `monitor_traffic(interface)`: Monitora pacotes de tráfego.
  - `dos_attack(target_ip, iface)`: Executa ataques DoS.
  - `check_connected_devices(interface)`: Verifica dispositivos conectados.

- **Menu Principal:**
  - Oferece acesso rápido às funcionalidades com seleção interativa.

## Uso
1. Execute o script como administrador.
2. Escolha a opção desejada no menu.
3. Siga as instruções fornecidas para cada módulo.

## Aviso Legal
Esta ferramenta foi desenvolvida exclusivamente para fins educacionais. O uso indevido pode violar leis locais ou internacionais. Utilize com responsabilidade.

---
