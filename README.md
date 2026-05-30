# Analisador Automatizado de Logs de Servidor

Este projeto foi desenvolvido de forma independente como parte da minha transição de carreira para a área de Segurança da Informação. Trata-se de um script automatizado em Python focado em segurança defensiva (Blue Team) para análise de arquivos de log e resposta a incidentes.

## 🚀 Funcionalidades

- **Detecção de Ataques de Força Bruta:** Monitora e identifica IPs com múltiplas falhas de autenticação (Erros HTTP 401 via requisições POST).
- **Detecção de Varredura de Diretórios (Directory Scanning):** Identifica tentativas de mapeamento de páginas inexistentes ou arquivos sensíveis (Erros HTTP 404).
- **Geração de Alertas:** Emite alertas automáticos classificando o nível de risco (Médio ou Alto) para auxiliar na tomada de decisão e bloqueio de IPs maliciosos.

## 🛠️ Tecnologias Utilizadas

- **Python 3**
- **Expressões Regulares (Biblioteca `re`)** para a filtragem e extração de padrões textuais nos logs.
- **Biblioteca `collections` (`Counter`)** para contagem eficiente de ocorrências de eventos suspeitos.
