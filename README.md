Descrição
O Packet Analyzer é uma aplicação desenvolvida em Python com PyQt5 para capturar, visualizar e analisar pacotes de rede em tempo real. Ideal para quem precisa monitorizar redes, diagnosticar problemas de conectividade ou realizar análises de tráfego para segurança.

A aplicação permite capturar pacotes de diferentes protocolos, incluindo TCP, UDP, ICMP e DNS, e visualizar informações detalhadas de cada pacote, como IP de origem, IP de destino, protocolo utilizado, timestamp e muito mais.

Funcionalidades
Captura em Tempo Real: Captura pacotes de rede ao vivo com a possibilidade de filtragem por protocolo.
Visualização de Pacotes: Mostra detalhes de pacotes como IPs, protocolo, timestamp, tempo e resumo do conteúdo.
Armazenamento de Dados: Armazena pacotes capturados numa base de dados SQLite para consultas futuras.
Exportação e Importação: Guarda capturas em ficheiros .pcap e permite carregamento de capturas anteriores.
Interface Intuitiva: Interface gráfica desenvolvida em PyQt5 para fácil navegação e uso.
Instalação
Clone este repositório:
bash
Copiar código
git clone https://github.com/teu-usuario/packet-analyzer.git
Navegue para a pasta do projeto:
bash
Copiar código
cd packet-analyzer
Instale as dependências necessárias:
bash
Copiar código
pip install -r requirements.txt
Requisitos
Python 3.x
PyQt5
Scapy

Utilização
Inicie a aplicação:

bash
Copiar código
python SI2.py
Na interface, selecione os protocolos que deseja monitorizar e clique em Start Capture para começar a captura dos pacotes.

Veja os pacotes capturados na tabela e clique em qualquer um para visualizar os detalhes.

Para parar a captura, clique em Stop Capture.

Utilize os botões Save Capture e Load Capture para salvar ou carregar capturas anteriores.
