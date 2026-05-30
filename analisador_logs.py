import re
from collections import Counter

# Simulando dados de um arquivo de log de servidor (Formatos comuns de acesso)
dados_log = """
192.168.1.50 - - [30/May/2026:12:01:02] "POST /login HTTP/1.1" 401 234
192.168.1.50 - - [30/May/2026:12:01:05] "POST /login HTTP/1.1" 401 234
192.168.1.12 - - [30/May/2026:12:01:10] "GET /index.html HTTP/1.1" 200 4523
192.168.1.50 - - [30/May/2026:12:01:12] "POST /login HTTP/1.1" 401 234
192.168.1.50 - - [30/May/2026:12:01:15] "POST /login HTTP/1.1" 401 234
192.168.1.50 - - [30/May/2026:12:01:18] "POST /login HTTP/1.1" 401 234
192.168.1.99 - - [30/May/2026:12:02:00] "GET /admin/config.php HTTP/1.1" 404 290
192.168.1.99 - - [30/May/2026:12:02:02] "GET /wp-login.php HTTP/1.1" 404 290
192.168.1.99 - - [30/May/2026:12:02:05] "GET /backup.sql HTTP/1.1" 404 290
"""

def analisar_tentativas_login(logs):
    print("=" * 60)
    print("             RELATÓRIO DE SEGURANÇA DA INFORMAÇÃO            ")
    print("=" * 60)
    
    # Expressão Regular (Regex) para extrair o IP e o código de status HTTP
    padrao = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\"(POST|GET).*\" (\d{3})"
    
    ips_falha_login = []
    ips_varredura_diretorio = []

    # Analisando linha por linha do log
    for linha in logs.strip().split("\n"):
        correspondencia = re.search(padrao, linha)
        if correspondencia:
            ip = correspondencia.group(1)
            metodo = correspondencia.group(2)
            status = correspondencia.group(3)

            # 401 significa Não Autorizado (comum em falhas de senha/força bruta)
            if status == "401" and metodo == "POST":
                ips_falha_login.append(ip)
            
            # 404 significa Não Encontrado (comum quando atacantes buscam páginas sensíveis)
            elif status == "404":
                ips_varredura_diretorio.append(ip)

    # Definindo limites (limiar de alerta)
    LIMITE_FORCA_BRUTA = 3
    LIMITE_VARREDURA = 2

    # Contando ocorrências por IP
    contagem_login = Counter(ips_falha_login)
    contagem_varredura = Counter(ips_varredura_diretorio)

    # Detecção de Força Bruta
    print("\n[+] Detectando possíveis ataques de Força Bruta (Múltiplas falhas de login):")
    for ip, qtd in contagem_login.items():
        if qtd >= LIMITE_FORCA_BRUTA:
            print(f" -> ALERTA: IP {ip} gerou {qtd} falhas de autenticação. Risco: Alto.")
        else:
            print(f" -> Info: IP {ip} gerou {qtd} falha(s). Monitorando...")

    # Detecção de Varredura de Diretórios
    print("\n[+] Detectando varreduras de diretórios/arquivos ocultos (Erros 404):")
    for ip, qtd in contagem_varredura.items():
        if qtd >= LIMITE_VARREDURA:
            print(f" -> ALERTA: IP {ip} fez {qtd} requisições a páginas inexistentes. Risco: Médio (Varredura ativa).")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    analisar_tentativas_login(dados_log)
