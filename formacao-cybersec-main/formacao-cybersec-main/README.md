# Formação CyberSec – Kensei & Vai na Web

Este é o repositório oficial da **Formação CyberSec**, uma parceria entre o **Kensei CyberSec Lab** e a escola **Vai na Web**. Aqui você encontrará todos os laboratórios práticos (`labs`), materiais de apoio e desafios propostos durante o curso.

Nosso objetivo é simples: transformar você em um profissional de segurança digital com mentalidade prática, base sólida e compromisso ético.

---

## 🏛️ Estrutura do Curso

A formação é dividida em três módulos progressivos, projetados para levar você do zero ao nível profissional.

### **Módulo 1: Fundamentos de Cibersegurança**
O alicerce. [cite_start]Aqui construímos sua base em redes, sistemas e os princípios da segurança ofensiva e defensiva[cite: 510, 511].
* [cite_start]**Tópicos:** Modelo CIA [cite: 512][cite_start], Cyber Kill Chain vs. MITRE ATT&CK, Infraestrutura de Redes [cite: 512][cite_start], Análise de Tráfego (`Wireshark`) [cite: 512][cite_start], Reconhecimento e OSINT, Escaneamento (`Nmap`)[cite: 512], Enumeração de Serviços e Análise de Vulnerabilidades.

### **Módulo 2: Defesa & Monitoramento (Blue Team)**
[cite_start]Com a base consolidada, aprendemos a construir, proteger e monitorar ambientes corporativos[cite: 513].
* [cite_start]**Tópicos:** Defesa em Profundidade, Hardening de Servidores, Firewalls e ACLs (`iptables`), OWASP Top 10 na prática, SIEM e Análise de Logs (`Wazuh`/`ELK`) [cite: 514][cite_start], IDS/IPS (`Snort`), Gestão de Vulnerabilidades e Patching, Segurança em Nuvem (AWS/GCP/Azure) [cite: 515] [cite_start]e Resposta a Incidentes (NIST)[cite: 516].

### **Módulo 3: Ethical Hacking (Red Team)**
[cite_start]É hora de pensar como o adversário[cite: 518]. Aplicamos todo o conhecimento para simular ataques, identificar falhas e reportá-las de forma profissional.
* [cite_start]**Tópicos:** Metodologia de Pentest [cite: 520][cite_start], Exploração de Vulnerabilidades (`Metasploit`, `Burp Suite`)[cite: 521], Quebra de Credenciais, Escalação de Privilégios (Linux/Windows), Movimentação Lateral, Evasão de Defesas e Elaboração de Relatórios Técnicos.

---

## 🚀 Como Iniciar um Laboratório

[cite_start]Todos os nossos labs são baseados em Docker para garantir um ambiente padronizado e seguro[cite: 18, 22]. Siga os passos abaixo para qualquer aula prática.

1.  **Clone o Repositório**
    [cite_start]Se você ainda não o fez, clone o projeto para sua máquina local[cite: 24, 71].
    ```bash
    git clone [https://github.com/Kensei-CyberSec-Lab/formacao-cybersec.git](https://github.com/Kensei-CyberSec-Lab/formacao-cybersec.git)
    ```

2.  **Navegue até a Pasta da Aula**
    [cite_start]Cada laboratório está contido em sua respectiva pasta de aula[cite: 85, 86].
    ```bash
    cd formacao-cybersec/modulo1-fundamentos/aula2-setup/
    ```

3.  **Inicie os Containers**
    [cite_start]Use o Docker Compose para construir e iniciar o ambiente da aula em background (`-d`)[cite: 87, 88].
    ```bash
    docker compose up -d
    ```
    [cite_start]*Para desligar o lab, use `docker stop <container_name>` [cite: 112] ou `docker compose down` na mesma pasta.*

4.  **Acesse os Ambientes**
    * **Acessar o terminal de um container (ex: Kali Linux):**
        ```bash
        docker exec -it kali_lab_4 /bin/bash 
        ```
    * **Acessar a aplicação web vulnerável (DVWA):**
        [cite_start]Abra seu navegador e acesse: `http://localhost:8080` [cite: 95]
        [cite_start](Credenciais padrão: `admin` / `password`)[cite: 97].

---

## 🥷 Compromisso Ético

O conhecimento adquirido aqui é uma ferramenta poderosa. Nosso código de conduta é inegociável e se baseia nos cânones do `(ISC)²`:

1.  [cite_start]**Proteger a sociedade, o bem comum e a infraestrutura.** [cite: 570]
2.  [cite_start]**Agir com honra, justiça e de acordo com a lei.** [cite: 571]
3.  [cite_start]**Prestar serviço diligente e competente.** [cite: 572]
4.  [cite_start]**Promover e proteger a profissão.** [cite: 573]

Toda técnica ofensiva ensinada tem como único propósito o aprendizado para **defesa**, **pesquisa**, **CTFs** ou **testes de invasão devidamente autorizados**. O uso indevido deste conhecimento é crime e viola os princípios desta comunidade.

---

## ❓ Suporte

Encontrou um problema ou tem alguma dúvida?
* [cite_start]Utilize o canal de comunicação oficial da turma[cite: 127, 598].
* Se for um problema técnico no repositório, abra uma **Issue** aqui no GitHub.

---

## 📜 Licença

Este projeto é distribuído sob a licença MIT.

---

*Cibersegurança é resistência. Vamos juntos hackear o futuro com ética e inteligência.*
