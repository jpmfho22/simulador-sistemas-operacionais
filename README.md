# 🧠 Simulador de Sistemas Operacionais


Projeto desenvolvido para a disciplina de **Sistemas Operacionais**, com o objetivo de simular os principais componentes e mecanismos internos de um Sistema Operacional real.

---

## 👨‍💻 Integrantes do grupo

- **João Pedro Magrin** — RA 113164  
- **Bruno Barroso dos Santos** — RA 114091  
- **Ryan Dias** — RA 113317  

---

## 🧩 Descrição do projeto

Este simulador implementa, de forma visual e interativa, os principais conceitos estudados em Sistemas Operacionais:

- 🧮 **Gerenciamento de Processos e Threads (PCB/TCB)**
- ⚙️ **Escalonamento de CPU** (`FCFS`, `RR` e `Prioridades`)
- 🧠 **Gerenciamento de Memória** com paginação e substituição (`FIFO` ou `LRU`)
- 💾 **Dispositivos de E/S** simulados (`block` e `char devices`)
- 📂 **Sistema de Arquivos** simplificado (criação, escrita e leitura)
- 🚀 **TLB (Translation Lookaside Buffer)** com estatísticas de acerto e erro
- 🪟 **Interface Gráfica (Tkinter)** com visualização em tempo real
- 📊 **Métricas**: turnaround, espera média, throughput, page faults, uso de dispositivos e TLB hits/misses

O projeto busca aproximar o comportamento de um **kernel educacional**, incluindo logs, bloqueio e desbloqueio de processos, e escalonamento de threads.

---

## 🚀 Como executar

### 1️⃣ Pré-requisitos

- Python **3.8+**
- Nenhuma biblioteca externa necessária (usa apenas módulos padrão do Python)

### 2️⃣ Execução padrão

Para executar o simulador com a interface gráfica:

```bash
python simulador.py
