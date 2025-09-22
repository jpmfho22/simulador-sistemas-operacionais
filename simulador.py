import argparse
import itertools
import logging
import random
import time
from enum import Enum, auto
import tkinter as tk
from tkinter import ttk, messagebox
import queue
import threading
import os

logging.basicConfig(filename="simulador_log.txt",
                    level=logging.INFO,
                    format="%(asctime)s %(message)s")

def logar(relogio, msg):
    logging.info(f"[{relogio}] {msg}")

class Estado(Enum):
    NOVO = auto()
    PRONTO = auto()
    EXECUTANDO = auto()
    BLOQUEADO = auto()
    TERMINADO = auto()

_pid_gen = itertools.count(1)
_tid_gen = itertools.count(1)

class ThreadUser:
    def __init__(self, nome, cpu_req, prioridade, processo):
        self.tid = next(_tid_gen)
        self.nome = nome
        self.cpu_req = cpu_req
        self.prioridade = int(prioridade)
        self.processo = processo
        self.estado = Estado.NOVO
        self.pc = 0
        self.regs = {"R0":0,"R1":0}
        self.chegada = None
        self.primeira_cpu = None
        self.fim = None
        self.cpu_usado = 0

    def terminou(self):
        return self.cpu_usado >= self.cpu_req

class Processo:
    def __init__(self, nome, cpu_req, mem_req, prioridade):
        self.pid = next(_pid_gen)
        self.nome = nome
        self.cpu_req = cpu_req
        self.mem_req = mem_req
        self.prioridade = int(prioridade)
        self.estado = Estado.NOVO
        self.pc = 0
        self.regs = {"R0":0,"R1":0}
        self.chegada = None
        self.primeira_cpu = None
        self.fim = None
        self.cpu_usado = 0
        self.threads = []
        self.arquivos_abertos = {}

    def add_thread(self, nome, cpu, prio):
        t = ThreadUser(nome, cpu, prio, self)
        self.threads.append(t)
        return t

    def terminou(self):
        if not self.threads:
            return self.cpu_usado >= self.cpu_req
        return all(t.terminou() for t in self.threads)

class Memoria:
    def __init__(self, tam_pagina, molduras):
        self.tam_pagina = tam_pagina
        self.molduras = molduras
        self.tabela = [None]*molduras
        self.livres = set(range(molduras))
        self.por_proc = {}
        self.page_faults = 0
        self.fila_fifo = []

    def paginas(self, bytes_):
        return (bytes_ + self.tam_pagina - 1)//self.tam_pagina

    def alocar(self, pid, bytes_):
        pags = self.paginas(bytes_)
        self.por_proc.setdefault(pid,{})
        for p in range(pags):
            if not self.livres:
                self.evict()
            if not self.livres:
                return False
            f = self.livres.pop()
            self.tabela[f] = (pid,p)
            self.por_proc[pid][p] = f
            self.fila_fifo.append(f)
        return True

    def evict(self):
        if not self.fila_fifo: return
        f = self.fila_fifo.pop(0)
        pid,p = self.tabela[f]
        if pid in self.por_proc and p in self.por_proc[pid]:
            del self.por_proc[pid][p]
        self.tabela[f] = None
        self.livres.add(f)
        self.page_faults += 1

    def liberar(self, pid):
        if pid not in self.por_proc: return
        for p, f in list(self.por_proc[pid].items()):
            self.tabela[f] = None
            self.livres.add(f)
            if f in self.fila_fifo:
                self.fila_fifo.remove(f)
        del self.por_proc[pid]

    def estat(self):
        return {"usadas": self.molduras - len(self.livres),
                "total": self.molduras,
                "page_faults": self.page_faults}

class Device:
    def __init__(self, nome, tipo, tempo_servico):
        self.nome = nome
        self.tipo = tipo
        self.tempo_servico = tempo_servico
        self.fila = queue.Queue()
        self.util_ticks = 0
        self.busy = False
        self.current = None

    def request(self, req):
        self.fila.put(req)

    def tick(self, relogio, kernel):
        if not self.busy and not self.fila.empty():
            self.current = self.fila.get()
            self.busy = True
            self.remaining = self.tempo_servico
            logar(relogio, f"Device {self.nome} iniciou req {self.current['id']}")
        if self.busy:
            self.remaining -= 1
            self.util_ticks += 1
            if self.remaining <= 0:
                self.busy = False
                finished = self.current
                logar(relogio, f"Device {self.nome} concluiu req {finished['id']}")
                kernel.interrupt_device(self, finished)
                self.current = None

class FileNode:
    def __init__(self, nome, tipo="file", parent=None):
        self.nome = nome
        self.tipo = tipo
        self.parent = parent
        self.children = {}
        self.content = bytearray()
        self.size = 0
        self.perms = "rw"
        self.created = None
        self.modified = None

    def path(self):
        if not self.parent: return "/"
        parts = []
        cur = self
        while cur and cur.parent:
            parts.append(cur.nome)
            cur = cur.parent
        return "/" + "/".join(reversed(parts))

class FileSystem:
    def __init__(self):
        self.root = FileNode("/", "dir", None)
        self.root.parent = None
        self.inodes = {"/": self.root}
        self.next_fid = 1
        self.open_table = {}

    def _resolve(self, path):
        if path == "/": return self.root
        parts = [p for p in path.split("/") if p]
        cur = self.root
        for p in parts:
            if p not in cur.children:
                return None
            cur = cur.children[p]
        return cur

    def mkdir(self, path):
        parts = [p for p in path.split("/") if p]
        cur = self.root
        for p in parts:
            if p not in cur.children:
                n = FileNode(p, "dir", cur)
                cur.children[p] = n
            cur = cur.children[p]
        return True

    def create(self, path):
        dirname = os.path.dirname(path)
        base = os.path.basename(path)
        dirn = self._resolve(dirname if dirname else "/")
        if dirn is None or dirn.tipo != "dir":
            return None
        if base in dirn.children:
            return None
        n = FileNode(base, "file", dirn)
        dirn.children[base] = n
        fid = self.next_fid
        self.next_fid += 1
        n.created = time.time()
        n.modified = n.created
        self.open_table[fid] = {"node": n, "pos": 0}
        return fid

    def open(self, path):
        node = self._resolve(path)
        if node is None or node.tipo != "file": return None
        fid = self.next_fid
        self.next_fid += 1
        self.open_table[fid] = {"node": node, "pos": 0}
        return fid

    def read(self, fid, size):
        if fid not in self.open_table: return None
        ent = self.open_table[fid]
        node = ent["node"]
        pos = ent["pos"]
        data = node.content[pos:pos+size]
        ent["pos"] += len(data)
        return bytes(data)

    def write(self, fid, data):
        if fid not in self.open_table: return False
        ent = self.open_table[fid]
        node = ent["node"]
        pos = ent["pos"]
        if pos > len(node.content):
            node.content += b'\x00' * (pos - len(node.content))
        node.content[pos:pos+len(data)] = data
        ent["pos"] += len(data)
        node.size = len(node.content)
        node.modified = time.time()
        return True

    def close(self, fid):
        if fid in self.open_table:
            del self.open_table[fid]
            return True
        return False

    def listdir(self, path):
        n = self._resolve(path)
        if n is None or n.tipo != "dir": return None
        return list(n.children.keys())

class Escalonador:
    def __init__(self, alg="FCFS", quantum=4, preemptivo=True, overhead=1):
        self.alg = alg.upper()
        self.quantum = quantum
        self.preemptivo = preemptivo
        self.overhead = overhead
        self.prontos = []
        self.exec = None
        self.exec_thread = None
        self.qtd_quantum = 0
        self.trocas = 0
        self.cpu_ticks = 0

    def adicionar_proc(self, proc, relogio):
        proc.estado = Estado.PRONTO
        if proc.chegada is None:
            proc.chegada = relogio
        self.prontos.append(proc)
        if self.alg == "PRIO":
            self.prontos.sort(key=lambda p: -p.prioridade)

    def adicionar_thread(self, thread, relogio):
        thread.estado = Estado.PRONTO
        if thread.chegada is None:
            thread.chegada = relogio
        self.prontos.append(thread)
        if self.alg == "PRIO":
            self.prontos.sort(key=lambda p: -p.prioridade)

    def proximo(self):
        if not self.prontos: return None
        if self.alg in ("FCFS","RR","PRIO"):
            return self.prontos.pop(0)

    def tick(self, relogio, kernel):
        if self.exec is None:
            p = self.proximo()
            if p:
                self.trocas += 1
                logar(relogio, f"Troca -> {'TID' if isinstance(p, ThreadUser) else 'PID'} {getattr(p,'tid',getattr(p,'pid',None))}")
                self.exec = p
                self.exec_thread = isinstance(p, ThreadUser)
                p.estado = Estado.EXECUTANDO
                if p.primeira_cpu is None:
                    p.primeira_cpu = relogio
                self.qtd_quantum = 0
        else:
            if isinstance(self.exec, ThreadUser):
                self.exec.cpu_usado += 1
                self.exec.pc += 1
                self.exec.processo.cpu_usado += 1
            else:
                self.exec.cpu_usado += 1
                self.exec.pc += 1
            self.qtd_quantum += 1
            self.cpu_ticks += 1
            if self.exec.terminou():
                self.exec.fim = relogio
                logar(relogio, f"{'TID' if self.exec_thread else 'PID'} {getattr(self.exec,'tid',getattr(self.exec,'pid',None))} terminou")
                self.exec.estado = Estado.TERMINADO
                kernel.finalizar(self.exec)
                self.exec = None
                kernel.avancar(self.overhead)
                return
            if self.alg == "RR" and self.qtd_quantum >= self.quantum:
                self.exec.estado = Estado.PRONTO
                self.prontos.append(self.exec)
                logar(relogio, f"Preempcao quantum {'TID' if self.exec_thread else 'PID'} {getattr(self.exec,'tid',getattr(self.exec,'pid',None))}")
                self.exec = None
                self.trocas += 1
                kernel.avancar(self.overhead)
                return
            if self.alg == "PRIO" and self.preemptivo and self.prontos:
                alto = max(self.prontos, key=lambda p: p.prioridade)
                curr_prio = self.exec.prioridade
                if alto.prioridade > curr_prio:
                    self.exec.estado = Estado.PRONTO
                    self.prontos.append(self.exec)
                    logar(relogio, f"Preempcao prio {'TID' if self.exec_thread else 'PID'} {getattr(self.exec,'tid',getattr(self.exec,'pid',None))}")
                    self.exec = None
                    self.trocas += 1
                    kernel.avancar(self.overhead)
                    return

class Kernel:
    def __init__(self, pag, mold, alg, quantum, seed=0):
        random.seed(seed)
        self.relogio = 0
        self.escalonador = Escalonador(alg, quantum, alg=="PRIO")
        self.mem = Memoria(pag, mold)
        self.procs = {}
        self.fim = []
        self.start = time.time()
        self.devices = []
        self.fs = FileSystem()
        self.device_map = {}
        self.next_req = 1

    def add_device(self, nome, tipo, tempo):
        d = Device(nome, tipo, tempo)
        self.devices.append(d)
        self.device_map[nome] = d

    def criar(self, nome, cpu, mem, prio):
        p = Processo(nome, cpu, mem, prio)
        if not self.mem.alocar(p.pid, p.mem_req):
            logar(self.relogio, f"Falha memoria PID {p.pid}")
            return None
        self.procs[p.pid] = p
        self.escalonador.adicionar_proc(p, self.relogio)
        logar(self.relogio, f"Proc criado PID {p.pid}")
        return p

    def criar_thread(self, pid, nome, cpu, prio):
        p = self.procs.get(pid)
        if not p: return None
        t = p.add_thread(nome, cpu, prio)
        self.escalonador.adicionar_thread(t, self.relogio)
        logar(self.relogio, f"Thread criada TID {t.tid} no PID {pid}")
        return t

    def finalizar(self, entidade):
        if isinstance(entidade, ThreadUser):
            proc = entidade.processo
            if entidade in proc.threads:
                proc.threads.remove(entidade)
            self.fim.append(entidade)
            if proc.terminou():
                self.mem.liberar(proc.pid)
                if proc.pid in self.procs:
                    del self.procs[proc.pid]
                self.fim.append(proc)
        else:
            if entidade.pid in self.procs:
                self.mem.liberar(entidade.pid)
                del self.procs[entidade.pid]
                self.fim.append(entidade)

    def tick(self):
        for d in self.devices:
            d.tick(self.relogio, self)
        self.escalonador.tick(self.relogio, self)
        self.relogio += 1

    def avancar(self, t=1):
        self.relogio += t

    def metricas(self):
        turn, wait, resp = [], [], []
        for p in self.fim + list(self.procs.values()):
            fim = p.fim if p.fim is not None else self.relogio
            if p.chegada is not None:
                turn.append(fim - p.chegada)
                wait.append(max(0, (fim - p.chegada) - p.cpu_usado))
                if p.primeira_cpu is not None:
                    resp.append(p.primeira_cpu - p.chegada)
        dev_util = {d.nome: d.util_ticks/max(1,self.relogio) for d in self.devices}
        return {
            "turnaround": sum(turn)/len(turn) if turn else 0,
            "espera": sum(wait)/len(wait) if wait else 0,
            "resposta": sum(resp)/len(resp) if resp else 0,
            "throughput": len([x for x in self.fim if isinstance(x,Processo)])/max(1,self.relogio),
            "trocas": self.escalonador.trocas,
            "page_faults": self.mem.page_faults,
            "device_util": dev_util
        }

    def interrupt_device(self, device, finished):
        target = finished.get("target")
        tipo = finished.get("tipo")
        if tipo == "io_block":
            ent = finished.get("entidade")
            ent.estado = Estado.PRONTO
            self.escalonador.adicionar_thread(ent, self.relogio) if isinstance(ent, ThreadUser) else self.escalonador.adicionar_proc(ent, self.relogio)
        if tipo == "fs_write":
            fid = finished.get("fid")
            data = finished.get("data")
            self.fs.write(fid, data)
            self.fs.close(fid)
        if tipo == "fs_read":
            fid = finished.get("fid")
            self.fs.close(fid)

    def io_request(self, entidade, device_name, tipo="io_block", payload=None, nonblocking=False):
        if device_name not in self.device_map: return False
        req = {"id": self.next_req, "entidade": entidade, "tipo": tipo, "payload": payload, "target": device_name, "fid": None, "data": None}
        self.next_req += 1
        if nonblocking:
            self.device_map[device_name].request(req)
            return True
        entidade.estado = Estado.BLOQUEADO
        self.device_map[device_name].request(req)
        return True

    def fs_create_and_write(self, path, data, device_name):
        fid = self.fs.create(path)
        if fid is None:
            return False
        req = {"id": self.next_req, "tipo":"fs_write", "fid": fid, "data": data, "entidade": None}
        self.next_req += 1
        self.device_map[device_name].request(req)
        return True

class Interface:
    def __init__(self, kernel):
        self.k = kernel
        self.root = tk.Tk()
        self.root.title("Simulador SO")
        self.root.geometry("1100x700")
        self.root.configure(bg="black")
        self.estilo = ttk.Style(self.root)
        self.estilo.theme_use("clam")
        self.estilo.configure("Horizontal.TProgressbar", troughcolor="white", background="green")
        self.frame_login = tk.Frame(self.root, bg="black")
        self.frame_login.pack(fill="both", expand=True)
        tk.Label(self.frame_login, text="Simulador de SO", font=("Segoe UI", 32, "bold"), fg="white", bg="black").pack(expand=True)
        self.barra = ttk.Progressbar(self.frame_login, length=400, mode="indeterminate")
        self.barra.pack(pady=30)
        self.barra.start(10)
        self.root.after(1000, self.mostrar)

    def mostrar(self):
        self.barra.stop()
        self.frame_login.pack_forget()
        f_geral = tk.Frame(self.root, bg="#f0f0f0")
        f_geral.pack(fill="both", expand=True)
        self.f_esq = tk.Frame(f_geral, bg="#f0f0f0")
        self.f_esq.pack(side="left", fill="both", expand=True)
        self.canvas = tk.Canvas(self.f_esq, bg="#f0f0f0")
        self.scroll = ttk.Scrollbar(self.f_esq, orient="vertical", command=self.canvas.yview)
        self.frame_scroll = tk.Frame(self.canvas, bg="#f0f0f0")
        self.frame_scroll.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0,0), window=self.frame_scroll, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scroll.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scroll.pack(side="right", fill="y")
        top = tk.Frame(self.frame_scroll, bg="#f0f0f0")
        top.pack(pady=10, fill="x")
        self.lbl_cpu = tk.Label(top, text="CPU: 0%", font=("Arial", 12), bg="#f0f0f0")
        self.lbl_cpu.pack(side="left", padx=10)
        self.bar_cpu = ttk.Progressbar(top, length=200, maximum=100, style="Horizontal.TProgressbar")
        self.bar_cpu.pack(side="left")
        self.lbl_mem = tk.Label(top, text=f"Memoria: 0/{self.k.mem.molduras}", font=("Arial", 12), bg="#f0f0f0")
        self.lbl_mem.pack(side="left", padx=20)
        self.bar_mem = ttk.Progressbar(top, length=200, maximum=self.k.mem.molduras, style="Horizontal.TProgressbar")
        self.bar_mem.pack(side="left")
        self.frame_proc = tk.Frame(self.frame_scroll, bg="#f0f0f0")
        self.frame_proc.pack(pady=10, fill="both", expand=True)
        self.cards = {}
        menu = tk.Frame(f_geral, bg="#e0e0e0", width=300)
        menu.pack(side="right", fill="y")
        menu.pack_propagate(False)
        tk.Label(menu, text="Programas", font=("Arial",14,"bold"), bg="#e0e0e0").pack(pady=8)
        progs=[("Calculadora",6,120,1),("Bloco de Notas",4,80,2),("Navegador",8,300,3)]
        for n,c,m,p in progs:
            tk.Button(menu, text=n, width=24,
                      command=lambda nn=n,cc=c,mm=m,pp=p: self.criar(nn,cc,mm,pp)).pack(pady=4)
        self.root.after(300, self.ciclo)


    def criar(self, nome, cpu, mem, prio):
        p = self.k.criar(nome, cpu, mem, prio)
        if p: self.add_card(p)

    def prompt_thread(self):
        win = tk.Toplevel(self.root)
        win.title("Criar Thread")
        tk.Label(win, text="PID:").grid(row=0,column=0)
        e = tk.Entry(win); e.grid(row=0,column=1)
        tk.Label(win, text="Nome:").grid(row=1,column=0)
        n = tk.Entry(win); n.grid(row=1,column=1)
        tk.Label(win, text="CPU:").grid(row=2,column=0)
        c = tk.Entry(win); c.grid(row=2,column=1)
        tk.Label(win, text="Prio:").grid(row=3,column=0)
        pr = tk.Entry(win); pr.grid(row=3,column=1)
        def ok():
            try:
                pid = int(e.get())
                cpu = int(c.get())
                prio = int(pr.get())
            except:
                return
            t = self.k.criar_thread(pid, n.get(), cpu, prio)
            if t:
                self.add_card_thread(t)
            win.destroy()
        tk.Button(win, text="OK", command=ok).grid(row=4,column=0,columnspan=2)

    def io_demo(self):
        procs = list(self.k.procs.values())
        if not procs: return
        p = procs[0]
        if p.threads:
            ent = p.threads[0]
        else:
            ent = p
        self.k.io_request(ent, list(self.k.device_map.keys())[0], tipo="io_block", payload=None, nonblocking=False)

    def fs_demo(self):
        dev = list(self.k.device_map.keys())[0]
        self.k.fs.mkdir("/docs")
        self.k.fs_create_and_write("/docs/arquivo.txt", b"hello mundo", dev)

    def add_card(self, p):
        card = tk.LabelFrame(self.frame_proc, text=f"{p.nome} (PID {p.pid})", padx=8, pady=6, bg="white")
        card.pack(fill="x", padx=20, pady=6)
        lbl_info = tk.Label(card, text=f"CPU {p.cpu_req} | Mem {p.mem_req} | Prio {p.prioridade}", bg="white")
        lbl_info.pack(anchor="w")
        lbl_estado = tk.Label(card, text=f"Estado: {p.estado.name}", bg="white")
        lbl_estado.pack(anchor="w")
        thr_btn = tk.Button(card, text="Criar Thread", bg="#337ab7", fg="white",
                  command=lambda pp=p: self.criar_thread_ui(pp))
        thr_btn.pack(anchor="e", pady=4)
        tk.Button(card, text="Encerrar", bg="red", fg="white",
                  command=lambda pp=p: self.encerrar(pp)).pack(anchor="e", pady=4)
        self.cards[p.pid] = {"frame":card,"lbl_info":lbl_info,"lbl_estado":lbl_estado}

    def add_card_thread(self, t):
        parent = self.cards.get(t.processo.pid)
        if not parent:
            self.add_card(t.processo)
            parent = self.cards[t.processo.pid]
        card = tk.Label(parent["frame"], text=f"  Thread {t.nome} (TID {t.tid})", bg="white", anchor="w")
        card.pack(fill="x")
        parent.setdefault("threads", {})[t.tid] = card

    def criar_thread_ui(self, p):
        t = self.k.criar_thread(p.pid, f"{p.nome}-T{len(p.threads)+1}", 3, p.prioridade)
        if t: self.add_card_thread(t)

    def encerrar(self, p):
        p.fim = self.k.relogio
        p.estado = Estado.TERMINADO
        self.k.finalizar(p)
        if p.pid in self.cards:
            self.cards[p.pid]["frame"].destroy()
            del self.cards[p.pid]

    def atualizar(self):
        for pid,p in list(self.k.procs.items()):
            if pid not in self.cards:
                self.add_card(p)
        for pid,c in list(self.cards.items()):
            p = self.k.procs.get(pid)
            if not p:
                c["frame"].destroy()
                del self.cards[pid]
                continue
            c["lbl_estado"].config(text=f"Estado: {p.estado.name} | CPU {p.cpu_usado}/{p.cpu_req} | Threads {len(p.threads)}")

    def status(self):
        usado = self.k.mem.estat()["usadas"]
        self.lbl_cpu.config(text=f"Clock: {self.k.relogio}")
        self.bar_cpu["value"] = min(100, (self.k.escalonador.cpu_ticks % 101))
        self.lbl_mem.config(text=f"Memoria: {usado}/{self.k.mem.molduras}")
        self.bar_mem["value"] = usado

    def ciclo(self):
        self.k.tick()
        self.atualizar()
        self.status()
        self.root.after(300, self.ciclo)

    def mostrar_metricas(self):
        m = self.k.metricas()
        lines = []
        for k,v in m.items():
            if k=="device_util":
                for dn,util in v.items():
                    lines.append(f"util {dn}: {util:.2f}")
            else:
                lines.append(f"{k}: {v}")
        txt = "\n".join(lines)
        messagebox.showinfo("Métricas", txt)

    def start(self):
        self.root.mainloop()

def args():
    p = argparse.ArgumentParser()
    p.add_argument("--algoritmo", choices=["FCFS","RR","PRIO"], default="FCFS")
    p.add_argument("--quantum", type=int, default=4)
    p.add_argument("--pagina", type=int, default=256)
    p.add_argument("--frames", type=int, default=32)
    p.add_argument("--seed", type=int, default=0)
    return p.parse_args()

def main():
    a = args()
    k = Kernel(a.pagina, a.frames, a.algoritmo, a.quantum, a.seed)
    k.add_device("hd0", "block", 6)
    k.add_device("tty0", "char", 3)
    for n,c,m,p in [("Demo1",10,120,1),("Demo2",7,200,2)]:
        p = k.criar(n,c,m,p)
        k.criar_thread(p.pid, f"{n}-t1", max(1,c//2), p.prioridade)
        k.criar_thread(p.pid, f"{n}-t2", max(1,c//3), max(1,p.prioridade-1))
    ui = Interface(k)
    ui.start()
    print(k.metricas())

if __name__ == "__main__":
    main()
