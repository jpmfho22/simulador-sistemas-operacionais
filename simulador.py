# simulador_so.py
# Versão estendida do simulador fornecido pelo aluno.
# Implementa os requisitos obrigatórios do enunciado + LRU opcional.

import argparse
import itertools
import logging
import random
import time
from enum import Enum, auto
import tkinter as tk
from tkinter import ttk, messagebox
import queue
import os
from collections import OrderedDict, deque

# ---------- Logging ----------
logging.basicConfig(filename="simulador_log.txt",
                    level=logging.INFO,
                    format="%(asctime)s %(message)s")

def logar(relogio, msg):
    s = f"[{relogio}] {msg}"
    logging.info(s)
    # também guardamos em memória para GUI
    SimLog.append(s)

# buffer de log em memória
SimLog = []

# ---------- Estados ----------
class Estado(Enum):
    NOVO = auto()
    PRONTO = auto()
    EXECUTANDO = auto()
    BLOQUEADO = auto()
    SUSPENSO = auto()
    PRONTO_SUSPENSO = auto()
    TERMINADO = auto()

# ---------- geradores ----------
_pid_gen = itertools.count(1)
_tid_gen = itertools.count(1)

# ---------- TLB simples (LRU) ----------
class TLB:
    def __init__(self, capacity=16):
        self.capacity = capacity
        self.cache = OrderedDict()
        self.hits = 0
        self.misses = 0

    def lookup(self, pid, vpage):
        key = (pid, vpage)
        if key in self.cache:
            self.hits += 1
            val = self.cache.pop(key)
            self.cache[key] = val
            return val
        self.misses += 1
        return None

    def insert(self, pid, vpage, frame):
        key = (pid,vpage)
        if key in self.cache:
            self.cache.pop(key)
        elif len(self.cache) >= self.capacity:
            self.cache.popitem(last=False)
        self.cache[key] = frame

    def stats(self):
        return {"hits": self.hits, "misses": self.misses, "size": len(self.cache), "capacity": self.capacity}

# ---------- ThreadUser (TCB) ----------
class ThreadUser:
    def __init__(self, nome, cpu_req, prioridade, processo):
        self.tid = next(_tid_gen)
        self.nome = nome
        self.cpu_req = cpu_req
        self.prioridade = int(prioridade)
        self.processo = processo
        self.estado = Estado.NOVO
        # registradores simulados
        self.regs = {"R0":0,"R1":0,"SP":0,"LR":0}
        self.pc = 0
        self.stack = []  # pilha lógica
        self.chegada = None
        self.primeira_cpu = None
        self.fim = None
        self.cpu_usado = 0

    def terminou(self):
        return self.cpu_usado >= self.cpu_req

# ---------- Processo (PCB) ----------
class Processo:
    def __init__(self, nome, cpu_req, mem_req, prioridade):
        self.pid = next(_pid_gen)
        self.nome = nome
        self.cpu_req = cpu_req
        self.mem_req = mem_req
        self.prioridade = int(prioridade)
        self.estado = Estado.NOVO
        self.pc = 0
        self.regs = {"R0":0,"R1":0,"SP":0}
        self.chegada = None
        self.primeira_cpu = None
        self.fim = None
        self.cpu_usado = 0
        self.threads = []
        self.arquivos_abertos = {}   # fid -> node
        # page table virtual->frame or -1 if not present
        self.page_table = {}
        self.swap_pages = set()

    def add_thread(self, nome, cpu, prio):
        t = ThreadUser(nome, cpu, prio, self)
        self.threads.append(t)
        return t

    def terminou(self):
        if not self.threads:
            return self.cpu_usado >= self.cpu_req
        return all(t.terminou() for t in self.threads)

# ---------- Memoria com política (FIFO ou LRU) ----------
class Memoria:
    def __init__(self, tam_pagina, molduras, replacement="FIFO"):
        self.tam_pagina = tam_pagina
        self.molduras = molduras
        self.tabela = [None]*molduras  # entries: (pid, vpage)
        self.livres = set(range(molduras))
        self.por_proc = {}  # pid -> {vpage: frame}
        self.page_faults = 0
        self.replacement = replacement.upper()
        self.fila_fifo = deque()
        # para LRU mantemos uso por frame
        self.lru_counter = 0
        self.frame_last_use = {}  # frame -> counter

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
            self.frame_last_use[f] = self.lru_counter; self.lru_counter += 1
        return True

    def access_frame(self, frame):
        # update LRU info
        self.frame_last_use[frame] = self.lru_counter; self.lru_counter += 1

    def evict(self):
        if not any(self.tabela):
            return
        if self.replacement == "FIFO":
            if not self.fila_fifo: return
            f = self.fila_fifo.popleft()
        else:  # LRU
            # choose frame with smallest last use
            used = {f: self.frame_last_use.get(f, 0) for f in range(self.molduras) if self.tabela[f] is not None}
            if not used: return
            f = min(used, key=used.get)
            # remove from fifo if present
            try:
                self.fila_fifo.remove(f)
            except ValueError:
                pass
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
                try:
                    self.fila_fifo.remove(f)
                except:
                    pass
            if f in self.frame_last_use:
                del self.frame_last_use[f]
        del self.por_proc[pid]

    def estat(self):
        return {"usadas": self.molduras - len(self.livres),
                "total": self.molduras,
                "page_faults": self.page_faults}

# ---------- Device ----------
class Device:
    def __init__(self, nome, tipo, tempo_servico):
        self.nome = nome
        self.tipo = tipo  # "block" or "char"
        self.tempo_servico = tempo_servico
        self.fila = queue.Queue()
        self.util_ticks = 0
        self.busy = False
        self.current = None
        self.remaining = 0

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

    def queue_snapshot(self):
        # retorna uma lista dos ids na fila (não consome)
        items = []
        q = self.fila
        try:
            # queue.Queue não permite iteração direta, então extraímos sem remover permanentemente
            temp=[]
            while True:
                item = q.get_nowait()
                items.append(item['id'])
                temp.append(item)
        except Exception:
            pass
        for it in temp:
            q.put(it)
        return {"busy": self.busy, "current_id": self.current['id'] if self.current else None,
                "remaining": self.remaining if self.busy else 0, "queue": items, "util": self.util_ticks}

# ---------- File system ----------
class FileNode:
    def __init__(self, nome, tipo="file", parent=None):
        self.nome = nome
        self.tipo = tipo
        self.parent = parent
        self.children = {}
        self.content = bytearray()
        self.size = 0
        self.perms = "rw"
        self.created = time.time()
        self.modified = self.created

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
        self.inodes = {"/": self.root}
        self.next_fid = 1
        self.open_table = {}   # fid -> {"node":node, "pos":pos}
        self.global_fd_table = {}  # path -> list(fids)

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
        self.global_fd_table.setdefault(path, []).append(fid)
        return fid

    def open(self, path):
        node = self._resolve(path)
        if node is None or node.tipo != "file": return None
        fid = self.next_fid
        self.next_fid += 1
        self.open_table[fid] = {"node": node, "pos": 0}
        self.global_fd_table.setdefault(path, []).append(fid)
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
            # remove do global tabela também
            node = self.open_table[fid]["node"]
            path = node.path()
            if path in self.global_fd_table:
                try:
                    self.global_fd_table[path].remove(fid)
                except ValueError:
                    pass
            del self.open_table[fid]
            return True
        return False

    def listdir(self, path):
        n = self._resolve(path)
        if n is None or n.tipo != "dir": return None
        return list(n.children.keys())

# ---------- Escalonador ----------
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
        # se não há nada em execução, escalona
        if self.exec is None:
            p = self.proximo()
            if p:
                self.trocas += 1
                tipo = "TID" if isinstance(p, ThreadUser) else "PID"
                idv = getattr(p,'tid',getattr(p,'pid',None))
                logar(relogio, f"Troca -> {tipo} {idv}")
                self.exec = p
                self.exec_thread = isinstance(p, ThreadUser)
                p.estado = Estado.EXECUTANDO
                if p.primeira_cpu is None:
                    p.primeira_cpu = relogio
                self.qtd_quantum = 0
        else:
            # executar tick na entidade
            if isinstance(self.exec, ThreadUser):
                self.exec.cpu_usado += 1
                self.exec.pc += 1
                self.exec.processo.cpu_usado += 1
            else:
                self.exec.cpu_usado += 1
                self.exec.pc += 1
            self.qtd_quantum += 1
            self.cpu_ticks += 1

            # se terminou
            if self.exec.terminou():
                self.exec.fim = relogio
                tipo = "TID" if self.exec_thread else "PID"
                idv = getattr(self.exec,'tid',getattr(self.exec,'pid',None))
                logar(relogio, f"{tipo} {idv} terminou")
                self.exec.estado = Estado.TERMINADO
                kernel.finalizar(self.exec)
                self.exec = None
                kernel.avancar(self.overhead)
                return

            # RR preempção por quantum
            if self.alg == "RR" and self.qtd_quantum >= self.quantum:
                self.exec.estado = Estado.PRONTO
                self.prontos.append(self.exec)
                tipo = "TID" if self.exec_thread else "PID"
                idv = getattr(self.exec,'tid',getattr(self.exec,'pid',None))
                logar(relogio, f"Preempcao quantum {tipo} {idv}")
                self.exec = None
                self.trocas += 1
                kernel.avancar(self.overhead)
                return

            # PRIO preemptivo (se configurado)
            if self.alg == "PRIO" and self.preemptivo and self.prontos:
                alto = max(self.prontos, key=lambda p: p.prioridade)
                curr_prio = self.exec.prioridade
                if alto.prioridade > curr_prio:
                    self.exec.estado = Estado.PRONTO
                    self.prontos.append(self.exec)
                    tipo = "TID" if self.exec_thread else "PID"
                    idv = getattr(self.exec,'tid',getattr(self.exec,'pid',None))
                    logar(relogio, f"Preempcao prio {tipo} {idv}")
                    self.exec = None
                    self.trocas += 1
                    kernel.avancar(self.overhead)
                    return

# ---------- Kernel ----------
class Kernel:
    def __init__(self, pag, mold, alg, quantum, seed=0, replacement="FIFO", overhead=1, preemptivo=True, tlb_capacity=16):
        random.seed(seed)
        self.relogio = 0
        self.escalonador = Escalonador(alg, quantum, preemptivo, overhead)
        self.mem = Memoria(pag, mold, replacement)
        self.procs = {}
        self.fim = []
        self.start = time.time()
        self.devices = []
        self.fs = FileSystem()
        self.device_map = {}
        self.next_req = 1
        self.tlb = TLB(tlb_capacity)

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
        # tick devices primeiro
        for d in self.devices:
            d.tick(self.relogio, self)
        # tick escalonador (CPU)
        self.escalonador.tick(self.relogio, self)
        self.relogio += 1

    def avancar(self, t=1):
        self.relogio += t

    def metricas(self):
        turn, wait, resp = [], [], []
        for p in self.fim + list(self.procs.values()):
            # somente processos (PCB) na lista final
            if isinstance(p, Processo):
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
            "device_util": dev_util,
            "tlb": self.tlb.stats()
        }

    def interrupt_device(self, device, finished):
        tipo = finished.get("tipo")
        if tipo == "io_block":
            ent = finished.get("entidade")
            if ent is None:
                return
            # desbloqueia entidade e coloca em prontos
            ent.estado = Estado.PRONTO
            if isinstance(ent, ThreadUser):
                self.escalonador.adicionar_thread(ent, self.relogio)
                logar(self.relogio, f"Thread TID {ent.tid} desbloqueada por {device.nome}")
            else:
                self.escalonador.adicionar_proc(ent, self.relogio)
                logar(self.relogio, f"Proc PID {ent.pid} desbloqueado por {device.nome}")
        elif tipo == "fs_write":
            fid = finished.get("fid")
            data = finished.get("data")
            try:
                self.fs.write(fid, data)
                self.fs.close(fid)
                logar(self.relogio, f"FS write finalizado fid {fid} via {device.nome}")
            except Exception as e:
                logar(self.relogio, f"Erro ao finalizar write fid {fid}: {e}")
        elif tipo == "fs_read":
            fid = finished.get("fid")
            try:
                self.fs.close(fid)
                logar(self.relogio, f"FS read finalizado fid {fid} via {device.nome}")
            except Exception as e:
                logar(self.relogio, f"Erro ao finalizar read fid {fid}: {e}")
        else:
            # tipo desconhecido, só log
            logar(self.relogio, f"Device {device.nome} terminou req desconhecido {finished.get('id')} tipo={tipo}")

    def io_request(self, entidade, device_name, tipo="io_block", payload=None, nonblocking=False):
        if device_name not in self.device_map: return False
        req = {"id": self.next_req, "entidade": entidade, "tipo": tipo, "payload": payload, "target": device_name, "fid": None, "data": None}
        self.next_req += 1
        if nonblocking:
            # registra no device sem bloquear a entidade
            self.device_map[device_name].request(req)
            logar(self.relogio, f"IO nonblocking req {req['id']} -> {device_name}")
            return True
        # bloqueante: muda estado e enfileira
        entidade.estado = Estado.BLOQUEADO
        self.device_map[device_name].request(req)
        logar(self.relogio, f"IO blocking req {req['id']} -> {device_name} (entidade bloqueada)")
        return True

    def fs_create_and_write(self, path, data, device_name):
        fid = self.fs.create(path)
        if fid is None:
            return False
        req = {"id": self.next_req, "tipo":"fs_write", "fid": fid, "data": data, "entidade": None}
        self.next_req += 1
        self.device_map[device_name].request(req)
        logar(self.relogio, f"FS write req {req['id']} -> {device_name} (path {path})")
        return True

    # wrappers de FS que atualizam tabela por processo
    def process_open(self, pid, path):
        p = self.procs.get(pid)
        if not p: return None
        fid = self.fs.open(path)
        if fid is None: return None
        p.arquivos_abertos[fid] = self.fs.open_table[fid]["node"]
        return fid

    def process_create_and_open(self, pid, path):
        p = self.procs.get(pid)
        if not p: return None
        fid = self.fs.create(path)
        if fid is None: return None
        p.arquivos_abertos[fid] = self.fs.open_table[fid]["node"]
        return fid

    def process_close(self, pid, fid):
        p = self.procs.get(pid)
        if not p: return False
        ok = self.fs.close(fid)
        if fid in p.arquivos_abertos:
            del p.arquivos_abertos[fid]
        return ok

# ---------- Interface (GUI) ----------
class Interface:
    def __init__(self, kernel):
        self.k = kernel
        self.root = tk.Tk()
        self.root.title("Simulador SO")
        self.root.geometry("1200x760")
        self.root.configure(bg="black")
        self.estilo = ttk.Style(self.root)
        self.estilo.theme_use("clam")
        self.estilo.configure("Horizontal.TProgressbar", troughcolor="white", background="green")
        self.frame_login = tk.Frame(self.root, bg="black")
        self.frame_login.pack(fill="both", expand=True)
        tk.Label(self.frame_login, text="Simulador de SO", font=("Segoe UI", 28, "bold"), fg="white", bg="black").pack(expand=True)
        self.barra = ttk.Progressbar(self.frame_login, length=400, mode="indeterminate")
        self.barra.pack(pady=20)
        self.barra.start(10)
        self.root.after(800, self.mostrar)

    def mostrar(self):
        self.barra.stop()
        self.frame_login.pack_forget()
        f_geral = tk.Frame(self.root, bg="#f0f0f0")
        f_geral.pack(fill="both", expand=True)
        # esquerda com canvas rolável
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
        top.pack(pady=8, fill="x")
        self.lbl_cpu = tk.Label(top, text="Clock: 0", font=("Arial", 12), bg="#f0f0f0")
        self.lbl_cpu.pack(side="left", padx=10)
        self.bar_cpu = ttk.Progressbar(top, length=200, maximum=100, style="Horizontal.TProgressbar")
        self.bar_cpu.pack(side="left")
        self.lbl_mem = tk.Label(top, text=f"Memoria: 0/{self.k.mem.molduras}", font=("Arial", 12), bg="#f0f0f0")
        self.lbl_mem.pack(side="left", padx=20)
        self.bar_mem = ttk.Progressbar(top, length=200, maximum=self.k.mem.molduras, style="Horizontal.TProgressbar")
        self.bar_mem.pack(side="left")
        # area processos
        self.frame_proc = tk.Frame(self.frame_scroll, bg="#f0f0f0")
        self.frame_proc.pack(pady=10, fill="both", expand=True)
        self.cards = {}
        # menu lateral com controles
        menu = tk.Frame(f_geral, bg="#e0e0e0", width=320)
        menu.pack(side="right", fill="y")
        menu.pack_propagate(False)
        tk.Label(menu, text="Operações", font=("Arial",14,"bold"), bg="#e0e0e0").pack(pady=8)
        # programas exemplo
        progs=[("Calculadora",6,120,1),("Bloco de Notas",4,80,2),("Navegador",8,300,3)]
        for n,c,m,p in progs:
            tk.Button(menu, text=n, width=28,
                      command=lambda nn=n,cc=c,mm=m,pp=p: self.criar(nn,cc,mm,pp)).pack(pady=4)
        tk.Button(menu, text="Criar Processo (manual)", width=28, command=self.prompt_proc).pack(pady=6)
        tk.Button(menu, text="Criar Thread (manual)", width=28, command=self.prompt_thread).pack(pady=6)
        tk.Button(menu, text="I/O Demo (bloqueante)", width=28, command=self.io_demo).pack(pady=6)
        tk.Button(menu, text="FS Demo (cria arquivo)", width=28, command=self.fs_demo).pack(pady=6)
        tk.Button(menu, text="Mostrar métricas", width=28, command=self.mostrar_metricas).pack(pady=6)
        tk.Button(menu, text="Mostrar Tabela de Páginas (PID)", width=28, command=self.show_page_table_prompt).pack(pady=6)
        tk.Button(menu, text="Painel Dispositivos", width=28, command=self.show_devices).pack(pady=6)
        tk.Button(menu, text="Painel FS", width=28, command=self.show_fs).pack(pady=6)
        tk.Button(menu, text="Mostrar Log", width=28, command=self.show_log).pack(pady=6)
        tk.Button(menu, text="Exportar Relatório", width=28, command=self.export_report).pack(pady=6)
        self.root.after(300, self.ciclo)

    # ---------- UI helpers ----------
    def criar(self, nome, cpu, mem, prio):
        p = self.k.criar(nome, cpu, mem, prio)
        if p:
            self.add_card(p)

    def prompt_proc(self):
        win = tk.Toplevel(self.root)
        win.title("Criar Processo")
        tk.Label(win, text="Nome:").grid(row=0,column=0)
        e = tk.Entry(win); e.grid(row=0,column=1)
        tk.Label(win, text="CPU:").grid(row=1,column=0)
        c = tk.Entry(win); c.grid(row=1,column=1)
        tk.Label(win, text="Mem(bytes):").grid(row=2,column=0)
        m = tk.Entry(win); m.grid(row=2,column=1)
        tk.Label(win, text="Prio:").grid(row=3,column=0)
        pr = tk.Entry(win); pr.grid(row=3,column=1)
        def ok():
            try:
                cpu = int(c.get()); mem = int(m.get()); prio = int(pr.get())
            except:
                return
            p = self.k.criar(e.get() or "P", cpu, mem, prio)
            if p: self.add_card(p)
            win.destroy()
        tk.Button(win, text="OK", command=ok).grid(row=4,column=0,columnspan=2)

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
                pid = int(e.get()); cpu = int(c.get()); prio = int(pr.get())
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
        ent = p.threads[0] if p.threads else p
        # usa o primeiro dispositivo
        dev = list(self.k.device_map.keys())[0]
        self.k.io_request(ent, dev, tipo="io_block", payload=None, nonblocking=False)

    def fs_demo(self):
        dev = list(self.k.device_map.keys())[0]
        self.k.fs.mkdir("/docs")
        self.k.fs_create_and_write("/docs/arquivo.txt", b"hello mundo", dev)
        messagebox.showinfo("FS", "Arquivo criado em /docs/arquivo.txt (escrito via device)")

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
            elif k=="tlb":
                lines.append(f"TLB hits: {v['hits']} misses: {v['misses']} size: {v['size']}/{v['capacity']}")
            else:
                lines.append(f"{k}: {v}")
        txt = "\n".join(lines)
        messagebox.showinfo("Métricas", txt)

    def show_page_table_prompt(self):
        win = tk.Toplevel(self.root)
        win.title("Tabela de Páginas")
        tk.Label(win, text="PID:").grid(row=0,column=0)
        e = tk.Entry(win); e.grid(row=0,column=1)
        def ok():
            try:
                pid = int(e.get())
            except:
                return
            self.show_page_table(pid)
            win.destroy()
        tk.Button(win, text="OK", command=ok).grid(row=1,column=0,columnspan=2)

    def show_page_table(self, pid):
        p = self.k.procs.get(pid)
        if not p:
            messagebox.showinfo("Erro", "PID não encontrado")
            return
        lines=[]
        lines.append(f"PID {pid} - Page Table")
        for vpage,frame in sorted(p.page_table.items()):
            lines.append(f"vpage {vpage} -> frame {frame}")
        messagebox.showinfo("Page Table", "\n".join(lines))

    def show_devices(self):
        win = tk.Toplevel(self.root)
        win.title("Dispositivos")
        for d in self.k.devices:
            info = d.queue_snapshot()
            tk.Label(win, text=f"{d.nome} ({d.tipo}) - busy: {info['busy']} current:{info['current_id']} rem:{info['remaining']} util:{info['util']}").pack(anchor="w")
            tk.Label(win, text=f"Fila: {info['queue']}").pack(anchor="w")

    def show_fs(self):
        win = tk.Toplevel(self.root)
        win.title("File System")
        root = self.k.fs.root
        def walk(node, pad=""):
            s = f"{pad}{node.nome}/" if node.tipo=="dir" else f"{pad}{node.nome}"
            tk.Label(win, text=s).pack(anchor="w")
            for c in node.children.values():
                walk(c, pad+"  ")
        walk(root)
        # mostrar tabela global de arquivos abertos
        tk.Label(win, text="--- Arquivos abertos (global) ---").pack(anchor="w")
        for path, fids in self.k.fs.global_fd_table.items():
            tk.Label(win, text=f"{path} -> fids {fids}").pack(anchor="w")

    def show_log(self):
        win = tk.Toplevel(self.root)
        win.title("Log")
        txt = tk.Text(win, width=100, height=30)
        txt.pack()
        for l in SimLog[-100:]:
            txt.insert("end", l+"\n")

    def export_report(self):
        m = self.k.metricas()
        report = []
        report.append("Relatório Simulador SO")
        report.append(f"Clock: {self.k.relogio}")
        for k,v in m.items():
            if k=="device_util":
                for dn,util in v.items():
                    report.append(f"util {dn}: {util:.2f}")
            elif k=="tlb":
                report.append(f"TLB hits: {v['hits']} misses: {v['misses']} size: {v['size']}/{v['capacity']}")
            else:
                report.append(f"{k}: {v}")
        fn = f"relatorio_{int(time.time())}.txt"
        with open(fn,"w") as f:
            f.write("\n".join(report))
        messagebox.showinfo("Relatório", f"Relatório salvo em {fn}")

    def start(self):
        self.root.mainloop()

# ---------- CLI and main ----------
def args():
    p = argparse.ArgumentParser()
    p.add_argument("--algoritmo", choices=["FCFS","RR","PRIO"], default="FCFS")
    p.add_argument("--quantum", type=int, default=4)
    p.add_argument("--pagina", type=int, default=256)
    p.add_argument("--frames", type=int, default=32)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--replacement", choices=["FIFO","LRU"], default="FIFO")
    p.add_argument("--overhead", type=int, default=1)
    p.add_argument("--preemptivo", type=lambda x: x.lower() in ("1","true","yes"), default=True)
    p.add_argument("--tlb", type=int, default=16)
    p.add_argument("--workload", type=str, default=None, help="caminho para workload JSON (opcional)")
    return p.parse_args()

def load_workload(path, kernel):
    import json
    try:
        with open(path,"r") as f:
            w = json.load(f)
    except Exception as e:
        print("Falha ao carregar workload:", e); return
    # formato esperado: lista de procs: {"nome":.., "cpu":.., "mem":.., "prio":.., "threads":[...]}
    for proc in w:
        p = kernel.criar(proc.get("nome","W"), proc.get("cpu",5), proc.get("mem",100), proc.get("prio",1))
        if not p: continue
        for t in proc.get("threads", []):
            kernel.criar_thread(p.pid, t.get("nome", f"{p.nome}-t"), t.get("cpu",1), t.get("prio", p.prioridade))

def main():
    a = args()
    k = Kernel(a.pagina, a.frames, a.algoritmo, a.quantum, a.seed, replacement=a.replacement, overhead=a.overhead, preemptivo=a.preemptivo, tlb_capacity=a.tlb)
    # devices
    k.add_device("hd0", "block", 6)
    k.add_device("tty0", "char", 3)
    # se houver workload
    if a.workload:
        load_workload(a.workload, k)
    else:
        for n,c,m,p in [("Demo1",10,120,1),("Demo2",7,200,2)]:
            p = k.criar(n,c,m,p)
            k.criar_thread(p.pid, f"{n}-t1", max(1,c//2), p.prioridade)
            k.criar_thread(p.pid, f"{n}-t2", max(1,c//3), max(1,p.prioridade-1))
    ui = Interface(k)
    ui.start()
    print(k.metricas())

if __name__ == "__main__":
    main()
