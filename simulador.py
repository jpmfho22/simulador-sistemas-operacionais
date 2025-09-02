from typing import List

class Thread:
    def __init__(self, id: int, burst: int):
        self.id = id
        self.burst = burst
        self.finalizada = False

    def executar(self):
        if self.burst > 0:
            self.burst -= 1
            if self.burst == 0:
                self.finalizada = True

class Processo:
    def __init__(self, id: int, prioridade: int, threads: List[Thread], memoria_req: int):
        self.id = id
        self.prioridade = prioridade
        self.threads = threads
        self.memoria_req = memoria_req

    def executar(self):
        for th in self.threads:
            if not th.finalizada:
                th.executar()
                return

    def finalizado(self):
        return all(th.finalizada for th in self.threads)

class CPU:
    def __init__(self):
        self.uso = 0

    def processar(self, processo: Processo):
        processo.executar()
        self.uso += 1

class Memoria:
    def __init__(self, total: int):
        self.total = total
        self.livre = total

    def alocar(self, processo: Processo):
        if processo.memoria_req <= self.livre:
            self.livre -= processo.memoria_req
            return True
        return False

    def liberar(self, processo: Processo):
        self.livre += processo.memoria_req

class Escalonador:
    def __init__(self):
        self.fila = []

    def adicionar(self, processo: Processo):
        self.fila.append(processo)

    def escalar(self):
        if self.fila:
            return self.fila.pop(0)
        return None

class SistemaSimulador:
    def __init__(self, processos: List[Processo], cpu: CPU, memoria: Memoria, escalonador: Escalonador):
        self.processos = processos
        self.cpu = cpu
        self.memoria = memoria
        self.escalonador = escalonador
        self.tempo = 0

    def executar(self):
        for p in self.processos:
            if self.memoria.alocar(p):
                self.escalonador.adicionar(p)

        while True:
            proc = self.escalonador.escalar()
            if proc is None:
                break
            self.cpu.processar(proc)
            print(f"T={self.tempo} -> Executando processo {proc.id}")
            self.tempo += 1
            if not proc.finalizado():
                self.escalonador.adicionar(proc)
            else:
                print(f"Processo {proc.id} finalizado")
                self.memoria.liberar(proc)

# ====================
# Exemplo simples
# ====================
if __name__ == "__main__":
    t1 = Thread(1, 3)
    t2 = Thread(2, 2)
    p1 = Processo(1, 1, [t1, t2], memoria_req=100)

    t3 = Thread(1, 4)
    p2 = Processo(2, 2, [t3], memoria_req=200)

    cpu = CPU()
    memoria = Memoria(500)
    escalonador = Escalonador()

    sistema = SistemaSimulador([p1, p2], cpu, memoria, escalonador)
    sistema.executar()
