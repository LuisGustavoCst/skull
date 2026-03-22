from __future__ import annotations

import ast
import base64
import csv
import ctypes
import html
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import secrets
import shutil
import socket
import ssl
import string
import subprocess
import sys
import time
import unicodedata
import uuid
import warnings
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, quote, urlparse

warnings.filterwarnings(
    "ignore",
    message=r"urllib3 .* doesn't match a supported version!",
    category=Warning,
)

import requests
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table


console = Console()
APP_TITLE = "SKULL TOOLBOX X"
REQUEST_TIMEOUT = 12


@dataclass
class ToolEntry:
    key: str
    name: str
    category: str
    description: str
    handler: Callable[[], None]
    aliases: tuple[str, ...] = field(default_factory=tuple)


class SkullToolbox:
    def __init__(self) -> None:
        self.console = console
        self.running = True
        self.started_at = time.time()
        self.last_action = "Inicializacao"
        self.action_count = 0
        self.network_calls = 0
        self.history: list[str] = []
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "SkullToolboxX/2.0 (+terminal utility panel)",
                "Accept": "application/json,text/plain,*/*",
            }
        )
        self.tools = self.build_tools()

    def build_tools(self) -> list[ToolEntry]:
        return [
            ToolEntry("01", "Consulta de IP", "REDE", "Geolocalizacao, ASN, fuso e organizacao", self.lookup_ip, ("IP",)),
            ToolEntry("02", "Calculadora CIDR", "REDE", "Sub-rede, broadcast e hosts", self.subnet_calculator, ("CIDR", "SUBNET")),
            ToolEntry("03", "Resolvedor DNS", "REDE", "Registros A, AAAA, MX e TXT", self.resolve_dns, ("DNS",)),
            ToolEntry("04", "Portas comuns", "REDE", "Checagem rapida de portas populares", self.check_common_ports, ("PORT", "PORTAS")),
            ToolEntry("05", "Inspetor SSL/TLS", "REDE", "Versao, cifra e validade do certificado", self.inspect_tls_certificate, ("TLS", "SSL")),
            ToolEntry("06", "Scanner de faixa de portas", "REDE", "Escaneia um intervalo de portas", self.port_range_scanner, ("PORTSCAN", "FAIXA")),
            ToolEntry("07", "Diagnostico HTTP", "WEB", "Status, redirecionamento, tempo e tamanho", self.check_http_site, ("HTTP",)),
            ToolEntry("08", "Cabecalhos HTTP", "WEB", "Leitura de cabecalhos importantes", self.inspect_http_headers, ("HEADERS",)),
            ToolEntry("09", "Consulta RDAP", "WEB", "Registro basico de dominio", self.domain_rdap_lookup, ("WHOIS", "RDAP")),
            ToolEntry("10", "Analisador de URL", "WEB", "Quebra a URL em partes", self.url_parser, ("URL",)),
            ToolEntry("11", "Decodificador JWT", "WEB", "Decodifica header e payload", self.jwt_decoder, ("JWT",)),
            ToolEntry("12", "Raio-X Steam publico", "JOGOS", "Perfil, amigos, grupos e visibilidade publica", self.steam_public_account_audit, ("STEAM", "STEAMID")),
            ToolEntry("13", "Intel de jogo Steam", "JOGOS", "Detalhes publicos de um jogo da Steam", self.steam_game_intel, ("APP", "JOGO")),
            ToolEntry("14", "Reviews Steam", "JOGOS", "Resumo e amostra de reviews de um jogo", self.steam_reviews_snapshot, ("REVIEWS", "REVIEW")),
            ToolEntry("15", "Radar de ofertas Steam", "JOGOS", "Ofertas, mais vendidos, lancamentos e links", self.steam_featured_radar, ("OFERTA", "DEALS")),
            ToolEntry("16", "Noticias do jogo Steam", "JOGOS", "Feed publico de noticias por app", self.steam_news_feed, ("NEWS", "NOTICIAS")),
            ToolEntry("17", "Busca de jogos Steam", "JOGOS", "Pesquisa jogo por nome na loja", self.steam_search_catalog, ("SEARCH", "BUSCAR")),
            ToolEntry("18", "Jogadores online Steam", "JOGOS", "Mostra quantos jogadores estao ativos agora", self.steam_current_players, ("PLAYERS", "ONLINE")),
            ToolEntry("19", "Comparador de jogos Steam", "JOGOS", "Compara dois jogos lado a lado", self.steam_compare_games, ("VS", "COMPAREGAME")),
            ToolEntry("20", "Inspetor de DLC Steam", "JOGOS", "Lista DLCs e links de um jogo", self.steam_dlc_inspector, ("DLC",)),
            ToolEntry("21", "Hash de texto", "DADOS", "MD5, SHA1, SHA256 e SHA512", self.hash_text, ("HASH",)),
            ToolEntry("22", "Hash de arquivo", "DADOS", "Checksums de arquivos locais", self.hash_file, ("FILEHASH",)),
            ToolEntry("23", "Laboratorio Base64", "DADOS", "Codifica e decodifica", self.base64_tool, ("BASE64",)),
            ToolEntry("24", "Laboratorio JSON", "DADOS", "Validacao e formatacao", self.pretty_json, ("JSON",)),
            ToolEntry("25", "Arena Regex", "DADOS", "Testa padroes e resultados", self.regex_tester, ("REGEX",)),
            ToolEntry("26", "Scanner de texto", "DADOS", "Estatisticas, linhas, palavras e hash", self.text_stats, ("TEXT",)),
            ToolEntry("27", "Conversor de data e timestamp", "DADOS", "Converte data local, UTC e Unix", self.datetime_converter, ("TS", "TIME")),
            ToolEntry("28", "Gerador de slug", "DADOS", "Cria slug, snake_case e texto limpo", self.slug_generator, ("SLUG",)),
            ToolEntry("29", "Resumo CSV", "DADOS", "Mostra colunas, linhas e amostra", self.csv_summary, ("CSV",)),
            ToolEntry("30", "Gerador de senha", "IDENTIDADE", "Senha forte sob medida", self.generate_password, ("PASSGEN",)),
            ToolEntry("31", "Auditoria de senha", "IDENTIDADE", "Forca e checklist", self.password_strength, ("PASS",)),
            ToolEntry("32", "Laboratorio CPF", "IDENTIDADE", "Gerar e validar CPF", self.cpf_tool, ("CPF",)),
            ToolEntry("33", "Consulta CEP", "IDENTIDADE", "Busca endereco via ViaCEP", self.lookup_cep, ("CEP",)),
            ToolEntry("34", "Laboratorio UUID e tokens", "IDENTIDADE", "uuid4, hex e urlsafe", self.uuid_token_lab, ("UUID", "TOKEN")),
            ToolEntry("35", "Radar do sistema", "LOCAL", "SO, Python, disco e ping", self.system_info, ("SYS",)),
            ToolEntry("36", "Raio-X do diretorio", "LOCAL", "Arquivos, tamanho e top extensoes", self.directory_snapshot, ("DIR", "FILES")),
            ToolEntry("37", "Calculadora segura", "LOCAL", "Calculadora com parser seguro", self.safe_calculator, ("CALC",)),
            ToolEntry("38", "Painel da sessao", "LOCAL", "Resumo da sessao atual", self.session_hud, ("HUD", "STATUS")),
            ToolEntry("39", "Pecas do PC", "LOCAL", "CPU, GPU, RAM, placa-mae e discos", self.pc_parts_inspector, ("HW", "PARTS")),
            ToolEntry("40", "Snapshot de processos", "LOCAL", "Top processos por memoria", self.process_snapshot, ("PROC", "PROCESS")),
            ToolEntry("41", "Conexoes ativas", "LOCAL", "Netstat com resumo de estados", self.active_connections, ("CONN", "NETSTAT")),
            ToolEntry("42", "Scanner de entropia", "LOCAL", "Analisa aleatoriedade de arquivo", self.file_entropy_scanner, ("ENT", "ENTROPY")),
            ToolEntry("43", "Cacador de duplicados", "LOCAL", "Encontra arquivos duplicados", self.duplicate_file_hunter, ("DUP", "DUPES")),
            ToolEntry("44", "Comparador de arquivos", "LOCAL", "Compara tamanho, hash e diferencas", self.file_comparator, ("COMPARE", "DIFF")),
            ToolEntry("45", "Busca em arquivos", "LOCAL", "Procura texto dentro de varios arquivos", self.file_search, ("GREP", "BUSCA")),
            ToolEntry("HELP", "Ajuda", "META", "Atalhos e navegacao", self.show_help, ("?", "H", "AJUDA")),
            ToolEntry("00", "Sair", "META", "Encerrar toolbox", self.exit_app, ("EXIT", "QUIT")),
        ]

    def run(self) -> None:
        while self.running:
            self.clear()
            self.render_banner()
            self.render_dashboard()
            self.render_menu()
            self.render_footer()
            choice = Prompt.ask("\n[bold #4dd0e1]Escolha uma opcao[/bold #4dd0e1]").strip().upper()
            self.dispatch(choice)

    def clear(self) -> None:
        os.system("cls" if os.name == "nt" else "clear")

    def render_banner(self) -> None:
        banner = r"""
   _____ __ ____  ____    __  __    __       ______            ____   __
  / ___// //_/ / / / /   / / / /   / /      /_  __/___  ____  / / /__/ /
  \__ \/ ,< / / / / /   / /_/ /   / /        / / / __ \/ __ \/ / / _  /
 ___/ / /| / /_/ / /___/ __  /   / /___     / / / /_/ / /_/ / / /  __/
/____/_/ |_\____/_____/_/ /_/   /_____/    /_/  \____/\____/_/_/\___/
        """
        subtitle = (
            "[bold white]feito pelo xnqz[/bold white]\n"
            "[#d0d7de]Rede, web, dados, identidade e sistema em um painel so[/#d0d7de]"
        )
        self.console.print(
            Panel.fit(
                f"[bold #4dd0e1]{banner}[/bold #4dd0e1]\n{subtitle}",
                title=f"[bold white]{APP_TITLE}[/bold white]",
                subtitle="[bold #ffb347]modo: destravado[/bold #ffb347]",
                border_style="#4dd0e1",
                box=box.DOUBLE,
            )
        )
            
    def render_dashboard(self) -> None:
        uptime = self.format_seconds(time.time() - self.started_at)
        stats = [
            Panel.fit(
                f"[bold #7fffd4]{len(self.tools) - 2}[/bold #7fffd4]\n[#d0d7de]ferramentas online[/#d0d7de]",
                title="[bold]Arsenal[/bold]",
                border_style="#00b894",
            ),
            Panel.fit(
                f"[bold #ffd166]{self.network_calls}[/bold #ffd166]\n[#d0d7de]chamadas de rede[/#d0d7de]",
                title="[bold]Rede[/bold]",
                border_style="#ffb347",
            ),
            Panel.fit(
                f"[bold #ff7aa2]{self.action_count}[/bold #ff7aa2]\n[#d0d7de]acoes executadas[/#d0d7de]",
                title="[bold]Sessao[/bold]",
                border_style="#ff5c8a",
            ),
            Panel.fit(
                f"[bold #a78bfa]{uptime}[/bold #a78bfa]\n[#d0d7de]tempo ativo[/#d0d7de]",
                title="[bold]Tempo[/bold]",
                border_style="#8b5cf6",
            ),
        ]
        self.console.print(Columns(stats, expand=True))

    def render_menu(self) -> None:
        categories = ["REDE", "WEB", "JOGOS", "DADOS", "IDENTIDADE", "LOCAL"]
        blocks: list[Panel] = []
        for category in categories:
            table = Table(box=box.SIMPLE_HEAVY, expand=True, show_header=True, header_style="bold white")
            table.add_column("ID", style="#4dd0e1", no_wrap=True)
            table.add_column("Ferramenta", style="white")
            for tool in self.tools:
                if tool.category == category:
                    table.add_row(tool.key, tool.name)
            blocks.append(
                Panel(
                    table,
                    title=f"[bold #ffd166]{category}[/bold #ffd166]",
                    border_style="#2d3436",
                    padding=(0, 1),
                )
            )
        self.console.print(Columns(blocks, equal=True, expand=True))

    def render_footer(self) -> None:
        history_text = " | ".join(self.history[-2:]) if self.history else "nenhum"
        footer = (
            "HELP ou AJUDA para comandos e notas\n"
            "Exemplos: HELP JOGOS | AJUDA 15 | HELP STEAM | HELP TODOS\n"
            "Atalhos gamer: STEAM APP REVIEW OFERTA NEWS SEARCH PLAYERS VS DLC\n"
            "Atalhos gerais: IP DNS JWT JSON PASS CEP SYS CALC HUD HW PROC CONN ENT DUP TS SLUG CSV\n"
            f"Ultima acao: [bold white]{self.last_action}[/bold white]\n"
            f"Historico: [bold white]{history_text}[/bold white]"
        )
        self.console.print(Panel(footer, border_style="#4dd0e1", box=box.ROUNDED))

    def dispatch(self, choice: str) -> None:
        if choice.startswith("HELP ") or choice.startswith("AJUDA "):
            _, topic = choice.split(" ", 1)
            self.record_action(f"Ajuda {topic.strip()}")
            self.clear()
            self.render_banner()
            self.show_help_topic(topic)
            return

        target = None
        for tool in self.tools:
            if choice == tool.key or choice in tool.aliases:
                target = tool
                break
        if target is None:
            self.show_error("Opcao invalida. Digite HELP ou AJUDA para ver os atalhos.")
            self.pause()
            return
        self.record_action(target.name)
        self.clear()
        self.render_banner()
        target.handler()

    def record_action(self, name: str) -> None:
        self.last_action = name
        self.action_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.history.append(f"{timestamp} {name}")
        self.history = self.history[-8:]

    def pause(self) -> None:
        input("\nPressione Enter para continuar...")

    def format_seconds(self, seconds: float) -> str:
        total = int(seconds)
        hours, rem = divmod(total, 3600)
        minutes, secs = divmod(rem, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    def normalize_url(self, value: str) -> str:
        value = value.strip()
        if not re.match(r"^https?://", value, re.IGNORECASE):
            value = f"https://{value}"
        return value

    def show_error(self, message: str) -> None:
        self.console.print(Panel.fit(f"[bold red]{message}[/bold red]", border_style="red"))

    def show_table(self, title: str, data: dict[str, Any]) -> None:
        table = Table(title=title, border_style="#00b894", box=box.SIMPLE_HEAVY)
        table.add_column("Campo", style="#4dd0e1", no_wrap=True)
        table.add_column("Valor", style="white")
        for key, value in data.items():
            if isinstance(value, (list, tuple, set)):
                rendered = " | ".join(str(item) for item in value) if value else "N/D"
            elif isinstance(value, dict):
                rendered = json.dumps(value, ensure_ascii=False)
            else:
                rendered = str(value)
            table.add_row(self.safe_terminal_text(str(key)), self.safe_terminal_text(rendered))
        self.console.print(table)

    def show_panel(self, title: str, content: str, color: str = "#4dd0e1") -> None:
        self.console.print(Panel(self.safe_terminal_text(content), title=title, border_style=color, box=box.ROUNDED))

    def fetch_json(self, url: str, **kwargs: Any) -> Any:
        self.network_calls += 1
        response = self.session.get(url, timeout=REQUEST_TIMEOUT, **kwargs)
        response.raise_for_status()
        return response.json()

    def fetch_response(self, url: str, **kwargs: Any) -> requests.Response:
        self.network_calls += 1
        response = self.session.get(url, timeout=REQUEST_TIMEOUT, **kwargs)
        response.raise_for_status()
        return response

    def xml_text(self, parent: ET.Element | None, tag: str, default: str = "N/D") -> str:
        if parent is None:
            return default
        child = parent.find(tag)
        if child is None or child.text is None:
            return default
        value = child.text.strip()
        return value if value else default

    def clean_steam_text(self, value: str | None, default: str = "N/D") -> str:
        if value is None:
            return default
        text = re.sub(r"(?i)<br\s*/?>", "\n", value)
        text = re.sub(r"<[^>]+>", "", text)
        text = html.unescape(text).replace("\r", "").strip()
        if not text:
            return default
        return self.safe_terminal_text(text)

    def safe_terminal_text(self, value: Any) -> str:
        text = str(value)
        encoding = getattr(self.console.file, "encoding", None) or sys.stdout.encoding or "utf-8"
        try:
            return text.encode(encoding, errors="replace").decode(encoding, errors="replace")
        except Exception:
            return text.encode("ascii", errors="replace").decode("ascii", errors="replace")

    def normalize_steam_profile_url(self, value: str) -> str:
        raw = value.strip()
        if not raw:
            raise ValueError("Digite uma URL, custom URL ou SteamID64.")

        if not re.match(r"^https?://", raw, re.IGNORECASE):
            if raw.isdigit():
                return f"https://steamcommunity.com/profiles/{raw}"
            return f"https://steamcommunity.com/id/{quote(raw.strip('/'))}"

        parsed = urlparse(raw)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) >= 2 and parts[0] in {"id", "profiles"}:
            return f"https://steamcommunity.com/{parts[0]}/{parts[1]}"
        raise ValueError("URL Steam invalida. Use um perfil em /id/ ou /profiles/.")

    def extract_steam_profile_counts(self, html_text: str) -> dict[str, str]:
        matches = re.findall(
            r'(?s)<span class="count_link_label">\s*([^<]+?)\s*</span>.*?<span class="profile_count_link_total">\s*([^<]+?)\s*</span>',
            html_text,
        )
        counts: dict[str, str] = {}
        for label, total in matches:
            counts[self.clean_steam_text(label)] = self.clean_steam_text(total)
        return counts

    def extract_steam_level(self, html_text: str) -> str:
        match = re.search(r'persona_name persona_level.*?friendPlayerLevelNum">(\d+)</span>', html_text, re.IGNORECASE | re.DOTALL)
        return match.group(1) if match else "N/D"

    def extract_steam_friend_counts(self, html_text: str) -> dict[str, int]:
        match = re.search(r"g_rgCounts\s*=\s*(\{.*?\});", html_text, re.IGNORECASE | re.DOTALL)
        if not match:
            return {}
        try:
            data = json.loads(match.group(1))
        except json.JSONDecodeError:
            return {}

        result: dict[str, int] = {}
        for key in ("cFriends", "cGroups"):
            value = data.get(key)
            if isinstance(value, int):
                result[key] = value
        return result

    def extract_steam_friend_names(self, html_text: str, limit: int = 8) -> list[str]:
        names: list[str] = []
        for block in re.findall(r'<div class="friend_block_content">(.*?)<br>', html_text, re.IGNORECASE | re.DOTALL):
            name = self.clean_steam_text(block, "").replace("\n", " ").strip()
            if name and name not in names:
                names.append(name)
            if len(names) >= limit:
                break
        return names

    def inspect_steam_games_visibility(self, base_url: str) -> dict[str, Any]:
        try:
            response = self.fetch_response(f"{base_url}/games?xml=1", allow_redirects=True)
        except requests.RequestException as exc:
            return {"status": "Falha ao consultar", "error": str(exc), "sample": []}

        if "/login/" in response.url or not response.text.lstrip().startswith("<?xml"):
            return {"status": "Oculta ou exige login", "error": "", "sample": []}

        try:
            root = ET.fromstring(response.text)
        except ET.ParseError:
            return {"status": "Formato inesperado", "error": "", "sample": []}

        sample: list[str] = []
        for game in root.findall(".//game")[:8]:
            name = self.xml_text(game, "name", "")
            if not name or name == "N/D":
                continue
            hours = self.xml_text(game, "hoursOnRecord", "")
            sample.append(f"{name} ({hours}h)" if hours and hours != "N/D" else name)
        return {"status": "Publica", "error": "", "sample": sample}

    def normalize_steam_appid(self, value: str) -> int:
        raw = value.strip()
        if not raw:
            raise ValueError("Digite um AppID ou URL da loja Steam.")
        if raw.isdigit():
            return int(raw)
        if not re.match(r"^https?://", raw, re.IGNORECASE):
            raise ValueError("Use um AppID numerico ou uma URL da loja Steam.")

        match = re.search(r"/app/(\d+)", urlparse(raw).path)
        if match:
            return int(match.group(1))
        raise ValueError("Nao encontrei um AppID nessa URL da Steam.")

    def fetch_steam_app_data(self, appid: int) -> dict[str, Any]:
        data = self.fetch_json(f"https://store.steampowered.com/api/appdetails?appids={appid}&cc=br&l=brazilian")
        entry = data.get(str(appid)) or {}
        if not entry.get("success"):
            raise ValueError("AppID nao encontrado ou indisponivel na loja Steam.")
        payload = entry.get("data")
        if not isinstance(payload, dict):
            raise ValueError("Resposta invalida da loja Steam.")
        return payload

    def fetch_steam_app_batch_data(self, appids: list[int]) -> dict[int, dict[str, Any]]:
        clean_ids = [str(appid) for appid in appids if isinstance(appid, int)]
        if not clean_ids:
            return {}
        payload = self.fetch_json(
            f"https://store.steampowered.com/api/appdetails?appids={','.join(clean_ids)}&cc=br&l=brazilian"
        )
        result: dict[int, dict[str, Any]] = {}
        for appid_text in clean_ids:
            entry = payload.get(appid_text) or {}
            if entry.get("success") and isinstance(entry.get("data"), dict):
                result[int(appid_text)] = entry["data"]
        return result

    def fetch_steam_review_summary(self, appid: int) -> dict[str, Any]:
        payload = self.fetch_json(
            f"https://store.steampowered.com/appreviews/{appid}?json=1&language=all&purchase_type=all&filter=summary&num_per_page=0"
        )
        return payload.get("query_summary") or {}

    def fetch_steam_current_player_count(self, appid: int) -> int | None:
        payload = self.fetch_json(f"https://api.steampowered.com/ISteamUserStats/GetNumberOfCurrentPlayers/v1/?appid={appid}")
        response = payload.get("response") or {}
        count = response.get("player_count")
        return int(count) if isinstance(count, int) else None

    def fetch_steam_store_search(self, term: str) -> list[dict[str, Any]]:
        payload = self.fetch_json(f"https://store.steampowered.com/api/storesearch/?term={quote(term)}&l=brazilian&cc=br")
        items = payload.get("items") or []
        return [item for item in items if isinstance(item, dict)]

    def format_price_cents(self, cents: int | None, currency: str = "BRL") -> str:
        if cents is None:
            return "N/D"
        value = cents / 100
        if currency == "BRL":
            return f"R$ {value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
        return f"{currency} {value:.2f}"

    def format_steam_price(self, data: dict[str, Any]) -> str:
        if data.get("is_free"):
            return "Gratuito"
        price = data.get("price_overview") or {}
        if isinstance(price, dict) and price.get("final") is not None:
            final_price = self.format_price_cents(price.get("final"), price.get("currency", "BRL"))
            discount = price.get("discount_percent") or 0
            if discount:
                initial_price = self.format_price_cents(price.get("initial"), price.get("currency", "BRL"))
                return f"{final_price} ({discount}% off, antes {initial_price})"
            return final_price
        return "Consulte a loja"

    def steam_platforms_text(self, platforms: dict[str, Any] | None) -> str:
        if not isinstance(platforms, dict):
            return "N/D"
        labels = []
        if platforms.get("windows"):
            labels.append("Windows")
        if platforms.get("mac"):
            labels.append("Mac")
        if platforms.get("linux"):
            labels.append("Linux")
        return " | ".join(labels) if labels else "N/D"

    def steam_review_score_text(self, desc: str) -> str:
        mapping = {
            "Overwhelmingly Positive": "Extremamente positivas",
            "Very Positive": "Muito positivas",
            "Mostly Positive": "Majoritariamente positivas",
            "Positive": "Positivas",
            "Mixed": "Mistas",
            "Mostly Negative": "Majoritariamente negativas",
            "Very Negative": "Muito negativas",
            "Overwhelmingly Negative": "Extremamente negativas",
            "Negative": "Negativas",
        }
        return mapping.get(desc, desc or "N/D")

    def trim_text(self, value: str, limit: int = 140) -> str:
        compact = re.sub(r"\s+", " ", value).strip()
        if len(compact) <= limit:
            return compact
        return compact[: limit - 3].rstrip() + "..."

    def format_unix_datetime(self, timestamp: int | float | None) -> str:
        if not timestamp:
            return "N/D"
        return datetime.fromtimestamp(float(timestamp)).strftime("%d/%m/%Y %H:%M")

    def steam_store_link(self, appid: int | str) -> str:
        return f"https://store.steampowered.com/app/{appid}"

    def run_command(self, args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
            check=False,
        )

    def run_powershell_json(self, script: str, timeout: int = 20) -> Any:
        process = self.run_command(["powershell", "-NoProfile", "-Command", script], timeout=timeout)
        if process.returncode != 0:
            raise RuntimeError(process.stderr.strip() or process.stdout.strip() or "Falha no PowerShell")
        output = process.stdout.strip()
        if not output:
            return None
        return json.loads(output)

    def query_registry_values(self, path: str) -> dict[str, str]:
        process = self.run_command(["reg", "query", path])
        if process.returncode != 0:
            return {}

        values: dict[str, str] = {}
        for line in process.stdout.splitlines():
            stripped = line.strip()
            if "REG_" not in stripped:
                continue
            parts = re.split(r"\s{2,}", stripped, maxsplit=2)
            if len(parts) == 3:
                name, _, value = parts
                values[name.strip()] = value.strip()
        return values

    def query_registry_recursive_value(self, path: str, value_name: str) -> list[str]:
        process = self.run_command(["reg", "query", path, "/s", "/v", value_name])
        if process.returncode != 0:
            return []

        matches: list[str] = []
        for line in process.stdout.splitlines():
            stripped = line.strip()
            if not stripped.startswith(value_name):
                continue
            parts = re.split(r"\s{2,}", stripped, maxsplit=2)
            if len(parts) == 3 and parts[2].strip():
                matches.append(parts[2].strip())
        return matches

    def registry_dword_to_int(self, value: str) -> int | None:
        value = value.strip().lower()
        try:
            if value.startswith("0x"):
                return int(value, 16)
            return int(value)
        except ValueError:
            return None

    def get_memory_status(self) -> dict[str, float]:
        if os.name != "nt":
            return {}

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return {}

        gib = 1024 ** 3
        return {
            "load_percent": float(status.dwMemoryLoad),
            "total_gb": round(status.ullTotalPhys / gib, 2),
            "available_gb": round(status.ullAvailPhys / gib, 2),
            "pagefile_total_gb": round(status.ullTotalPageFile / gib, 2),
        }

    def list_windows_drives(self) -> list[str]:
        if os.name != "nt":
            return [str(Path.cwd().anchor or "/")]

        drives: list[str] = []
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            if os.path.exists(root):
                drives.append(root)
        return drives

    def calc_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        data_len = len(data)
        for count in freq:
            if count == 0:
                continue
            p = count / data_len
            entropy -= p * math.log2(p)
        return entropy

    def sha256_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def sha1_file(self, path: Path) -> str:
        digest = hashlib.sha1()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def first_difference_offset(self, path_a: Path, path_b: Path) -> int | None:
        offset = 0
        with path_a.open("rb") as file_a, path_b.open("rb") as file_b:
            while True:
                chunk_a = file_a.read(65536)
                chunk_b = file_b.read(65536)
                if chunk_a == chunk_b:
                    if not chunk_a:
                        return None
                    offset += len(chunk_a)
                    continue
                limit = min(len(chunk_a), len(chunk_b))
                for index in range(limit):
                    if chunk_a[index] != chunk_b[index]:
                        return offset + index
                return offset + limit

    def slugify_text(self, value: str) -> str:
        normalized = unicodedata.normalize("NFKD", value)
        ascii_text = normalized.encode("ascii", "ignore").decode("ascii")
        cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", ascii_text.lower()).strip("-")
        return cleaned or "texto-vazio"

    def parse_datetime_value(self, raw_value: str) -> datetime:
        raw_value = raw_value.strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                return datetime.strptime(raw_value, fmt)
            except ValueError:
                continue
        return datetime.fromisoformat(raw_value)

    def find_tool(self, query: str) -> ToolEntry | None:
        normalized = query.strip().upper()
        for tool in self.tools:
            if normalized == tool.key.upper():
                return tool
            if normalized == tool.name.upper():
                return tool
            if normalized in tool.aliases:
                return tool
        return None

    def get_tools_by_category(self, category: str) -> list[ToolEntry]:
        return [tool for tool in self.tools if tool.category == category]

    def render_help_table(self, title: str, tools: list[ToolEntry]) -> None:
        table = Table(title=title, border_style="#ffb347", box=box.SIMPLE_HEAVY)
        table.add_column("Codigo", style="#4dd0e1", no_wrap=True)
        table.add_column("Ferramenta", style="white")
        table.add_column("Descricao", style="white")
        table.add_column("Atalhos", style="white")
        for tool in tools:
            aliases = ", ".join(tool.aliases) if tool.aliases else "-"
            table.add_row(tool.key, tool.name, tool.description, aliases)
        self.console.print(table)

    def show_help_topic(self, topic: str | None = None) -> None:
        if topic is None:
            self.show_help()
            return

        normalized = topic.strip().upper()
        categories = ["REDE", "WEB", "JOGOS", "DADOS", "IDENTIDADE", "LOCAL"]

        if normalized in {"GERAL", "HELP", "AJUDA"}:
            self.show_help()
            return

        if normalized in {"COMANDOS", "ATALHOS"}:
            commands_text = (
                "[bold]Comandos de ajuda[/bold]\n"
                "HELP\n"
                "Mostra a ajuda geral.\n\n"
                "HELP REDE / HELP WEB / HELP JOGOS / HELP DADOS / HELP IDENTIDADE / HELP LOCAL\n"
                "Mostra as ferramentas daquela categoria.\n\n"
                "HELP 15 / HELP 17 / HELP 18 / HELP 19 / HELP DLC / HELP STEAM\n"
                "Mostra ajuda detalhada de uma ferramenta por codigo ou alias.\n\n"
                "HELP TODOS\n"
                "Lista todas as ferramentas com descricao e atalhos."
            )
            self.show_panel("[bold]Comandos de Ajuda[/bold]", commands_text, "#ffb347")
            self.pause()
            return

        if normalized == "TODOS":
            tools = [tool for tool in self.tools if tool.category != "META"]
            self.render_help_table("[bold]Todas as Ferramentas[/bold]", tools)
            self.pause()
            return

        if normalized in categories:
            tools = self.get_tools_by_category(normalized)
            self.render_help_table(f"[bold]Ajuda da Categoria {normalized}[/bold]", tools)
            self.pause()
            return

        tool = self.find_tool(normalized)
        if tool is not None:
            detail = {
                "Codigo": tool.key,
                "Ferramenta": tool.name,
                "Categoria": tool.category,
                "Descricao": tool.description,
                "Atalhos": ", ".join(tool.aliases) if tool.aliases else "-",
                "Como abrir": f"Digite {tool.key} ou um dos atalhos acima",
            }
            self.show_table("[bold]Ajuda da Ferramenta[/bold]", detail)
            self.pause()
            return

        self.show_error("Topico de ajuda nao encontrado. Use HELP, AJUDA, HELP JOGOS, HELP 15, HELP 17, HELP DLC ou HELP TODOS.")
        self.pause()

    def show_help(self) -> None:
        help_text = (
            "[bold]Como usar[/bold]\n"
            "Digite o codigo da ferramenta ou um alias curto.\n\n"
            "[bold]Exemplos[/bold]\n"
            "01 / IP / DNS / JWT / STEAM / APP / REVIEW / OFERTA / NEWS / SEARCH / PLAYERS / VS / DLC / JSON / PASS / CEP / SYS / CALC / HW / PROC / CONN / TS / SLUG / CSV / HELP / AJUDA\n"
            "HELP REDE / HELP JOGOS / AJUDA 15 / HELP 17 / HELP DLC / HELP TODOS\n\n"
            "[bold]Notas[/bold]\n"
            "- Sem login e sem configuracao obrigatoria.\n"
            "- Ferramentas web dependem da internet.\n"
            "- Ferramentas locais funcionam sem rede.\n"
            "- O painel guarda historico apenas durante a sessao atual."
        )
        self.show_panel("[bold]Ajuda[/bold]", help_text, "#ffb347")
        self.pause()

    def exit_app(self) -> None:
        self.console.print("[bold green]Encerrando toolbox...[/bold green]")
        self.running = False

    def session_hud(self) -> None:
        total_tools = len([tool for tool in self.tools if tool.category != "META"])
        uptime = self.format_seconds(time.time() - self.started_at)
        result = {
            "App": APP_TITLE,
            "Iniciado em": datetime.fromtimestamp(self.started_at).strftime("%Y-%m-%d %H:%M:%S"),
            "Tempo ativo": uptime,
            "Ferramentas": total_tools,
            "Acoes": self.action_count,
            "Chamadas de rede": self.network_calls,
            "Ultima acao": self.last_action,
            "Historico": self.history[-5:] or ["nenhum"],
        }
        self.show_table("[bold]Painel da Sessao[/bold]", result)
        self.pause()

    def lookup_ip(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Consulta de IP[/bold #4dd0e1]", border_style="#4dd0e1"))
        ip_value = Prompt.ask("Digite um IP ou deixe vazio para consultar o IP atual").strip()

        try:
            if ip_value:
                ipaddress.ip_address(ip_value)
                url = f"https://ipapi.co/{ip_value}/json/"
            else:
                url = "https://ipapi.co/json/"

            with self.console.status("[bold green]Consultando IP...[/bold green]"):
                data = self.fetch_json(url)

            if data.get("error"):
                self.show_error(str(data.get("reason", "Falha ao consultar IP.")))
                self.pause()
                return

            result = {
                "IP": data.get("ip", "N/D"),
                "Versao": data.get("version", "N/D"),
                "Cidade": data.get("city", "N/D"),
                "Regiao": data.get("region", "N/D"),
                "Pais": data.get("country_name", "N/D"),
                "Latitude": data.get("latitude", "N/D"),
                "Longitude": data.get("longitude", "N/D"),
                "Fuso horario": data.get("timezone", "N/D"),
                "CEP": data.get("postal", "N/D"),
                "ASN": data.get("asn", "N/D"),
                "Organizacao": data.get("org", "N/D"),
            }
            self.show_table("[bold]Inteligencia de IP[/bold]", result)
        except ValueError:
            self.show_error("IP invalido.")
        except requests.RequestException as exc:
            self.show_error(f"Erro de rede: {exc}")

        self.pause()

    def subnet_calculator(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Calculadora CIDR[/bold #4dd0e1]", border_style="#4dd0e1"))
        raw = Prompt.ask("Digite a rede ou IP/CIDR (ex: 192.168.0.10/24)")

        try:
            interface = ipaddress.ip_interface(raw)
            network = interface.network
            hosts = list(network.hosts())
            first_host = hosts[0] if hosts else "N/D"
            last_host = hosts[-1] if hosts else "N/D"
            result = {
                "IP": interface.ip,
                "Rede": network.network_address,
                "Mascara": network.netmask,
                "Broadcast": network.broadcast_address,
                "Prefixo": f"/{network.prefixlen}",
                "Total de enderecos": network.num_addresses,
                "Primeiro host": first_host,
                "Ultimo host": last_host,
                "Privado": "sim" if interface.ip.is_private else "nao",
                "Versao": interface.version,
            }
            self.show_table("[bold]Quebra CIDR[/bold]", result)
        except ValueError as exc:
            self.show_error(f"Entrada invalida: {exc}")

        self.pause()

    def resolve_dns(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Resolvedor DNS[/bold #4dd0e1]", border_style="#4dd0e1"))
        domain = Prompt.ask("Digite o dominio").strip().lower()
        if not domain:
            self.show_error("Dominio nao pode ficar vazio.")
            self.pause()
            return

        try:
            with self.console.status("[bold green]Resolvendo DNS...[/bold green]"):
                ipv4 = sorted({item[4][0] for item in socket.getaddrinfo(domain, None, socket.AF_INET)})
                try:
                    ipv6 = sorted({item[4][0] for item in socket.getaddrinfo(domain, None, socket.AF_INET6)})
                except socket.gaierror:
                    ipv6 = []

                mx_response = self.fetch_json("https://dns.google/resolve", params={"name": domain, "type": "MX"})
                txt_response = self.fetch_json("https://dns.google/resolve", params={"name": domain, "type": "TXT"})
                mx_values = [answer.get("data", "") for answer in mx_response.get("Answer") or [] if answer.get("data")]
                txt_values = [answer.get("data", "") for answer in txt_response.get("Answer") or [] if answer.get("data")]

            result = {
                "Dominio": domain,
                "IPv4": ipv4 or ["nenhum"],
                "IPv6": ipv6 or ["nenhum"],
                "MX": mx_values[:6] or ["nenhum"],
                "TXT": txt_values[:4] or ["nenhum"],
            }
            self.show_table("[bold]Inteligencia DNS[/bold]", result)
        except socket.gaierror:
            self.show_error("Nao foi possivel resolver o dominio.")
        except requests.RequestException as exc:
            self.show_error(f"Erro de rede: {exc}")

        self.pause()

    def check_common_ports(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Verificador de Portas Comuns[/bold #4dd0e1]", border_style="#4dd0e1"))
        host = Prompt.ask("Digite o host ou IP").strip()
        if not host:
            self.show_error("Host nao pode ficar vazio.")
            self.pause()
            return

        common_ports = {
            21: "FTP",
            22: "SSH",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            5432: "Postgres",
            6379: "Redis",
            8080: "HTTP-Alt",
        }

        results: dict[str, str] = {}
        with self.console.status("[bold green]Verificando portas comuns...[/bold green]"):
            for port, label in common_ports.items():
                try:
                    with socket.create_connection((host, port), timeout=0.8):
                        status = "aberta"
                except OSError:
                    status = "fechada"
                results[f"{port}/{label}"] = status

        self.show_table("[bold]Portas Comuns[/bold]", results)
        self.pause()

    def inspect_tls_certificate(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Inspetor SSL/TLS[/bold #4dd0e1]", border_style="#4dd0e1"))
        host = Prompt.ask("Digite o dominio").strip()
        if not host:
            self.show_error("Dominio nao pode ficar vazio.")
            self.pause()
            return

        try:
            with self.console.status("[bold green]Inspecionando certificado...[/bold green]"):
                context = ssl.create_default_context()
                with socket.create_connection((host, 443), timeout=REQUEST_TIMEOUT) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as secure_socket:
                        cert = secure_socket.getpeercert()
                        cipher = secure_socket.cipher()
                        tls_version = secure_socket.version()
                        subject = dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {}
                        issuer = dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {}
                        sans = cert.get("subjectAltName", [])

            result = {
                "Host": host,
                "TLS": tls_version,
                "Cifra": cipher[0] if cipher else "N/D",
                "Bits": cipher[2] if cipher else "N/D",
                "Emitido para": subject.get("commonName", "N/D"),
                "Emitido por": issuer.get("commonName", "N/D"),
                "Valido de": cert.get("notBefore", "N/D"),
                "Valido ate": cert.get("notAfter", "N/D"),
                "Total de SANs": len(sans),
            }
            self.show_table("[bold]Relatorio TLS[/bold]", result)
        except Exception as exc:
            self.show_error(f"Falha ao analisar TLS: {exc}")

        self.pause()

    def check_http_site(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Diagnostico HTTP[/bold #4dd0e1]", border_style="#4dd0e1"))
        url = self.normalize_url(Prompt.ask("Digite a URL"))

        try:
            with self.console.status("[bold green]Consultando site...[/bold green]"):
                response = self.fetch_response(url, allow_redirects=True)

            lower_headers = {key.lower(): value for key, value in response.headers.items()}
            security_headers = [
                "content-security-policy",
                "strict-transport-security",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
            ]
            security_score = sum(1 for header in security_headers if header in lower_headers)
            result = {
                "URL final": response.url,
                "Status": response.status_code,
                "Motivo": response.reason,
                "Tempo": f"{response.elapsed.total_seconds():.3f}s",
                "Redirecionamentos": len(response.history),
                "Servidor": response.headers.get("Server", "N/D"),
                "Content-Type": response.headers.get("Content-Type", "N/D"),
                "Bytes": len(response.content),
                "Cabecalhos de seguranca": f"{security_score}/{len(security_headers)}",
            }
            self.show_table("[bold]Relatorio HTTP[/bold]", result)
        except requests.RequestException as exc:
            self.show_error(f"Falha ao consultar site: {exc}")

        self.pause()

    def inspect_http_headers(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Cabecalhos HTTP[/bold #4dd0e1]", border_style="#4dd0e1"))
        url = self.normalize_url(Prompt.ask("Digite a URL"))
        interesting = [
            "Server",
            "Date",
            "Content-Type",
            "Content-Length",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "Cache-Control",
            "Set-Cookie",
        ]

        try:
            with self.console.status("[bold green]Lendo headers...[/bold green]"):
                response = self.fetch_response(url, allow_redirects=True)

            result = {"URL final": response.url, "Status": response.status_code}
            for header in interesting:
                result[header] = response.headers.get(header, "Nao definido")
            self.show_table("[bold]Dump de Cabecalhos[/bold]", result)
        except requests.RequestException as exc:
            self.show_error(f"Erro ao consultar headers: {exc}")

        self.pause()

    def domain_rdap_lookup(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Consulta RDAP[/bold #4dd0e1]", border_style="#4dd0e1"))
        domain = Prompt.ask("Digite o dominio").strip().lower()
        if not domain:
            self.show_error("Dominio nao pode ficar vazio.")
            self.pause()
            return

        try:
            with self.console.status("[bold green]Consultando RDAP...[/bold green]"):
                data = self.fetch_json(f"https://rdap.org/domain/{domain}")

            events = data.get("events") or []
            created = next((event.get("eventDate") for event in events if event.get("eventAction") == "registration"), "N/D")
            expires = next((event.get("eventDate") for event in events if event.get("eventAction") == "expiration"), "N/D")
            statuses = data.get("status") or []
            result = {
                "Dominio": data.get("ldhName", domain),
                "Identificador": data.get("handle", "N/D"),
                "Port43": data.get("port43", "N/D"),
                "Criado": created,
                "Expira": expires,
                "Status": statuses[:6] or ["N/D"],
            }
            self.show_table("[bold]Inteligencia RDAP[/bold]", result)
        except requests.RequestException as exc:
            self.show_error(f"Erro na consulta RDAP: {exc}")

        self.pause()

    def url_parser(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Analisador de URL[/bold #4dd0e1]", border_style="#4dd0e1"))
        raw_url = self.normalize_url(Prompt.ask("Digite a URL"))
        parsed = urlparse(raw_url)
        query = parse_qs(parsed.query)

        result = {
            "URL original": raw_url,
            "Esquema": parsed.scheme or "N/D",
            "Host": parsed.hostname or "N/D",
            "Porta": parsed.port or "padrao",
            "Caminho": parsed.path or "/",
            "Query": parsed.query or "N/D",
            "Fragmento": parsed.fragment or "N/D",
            "Usuario": parsed.username or "N/D",
            "Senha": "***" if parsed.password else "N/D",
        }
        self.show_table("[bold]Quebra da URL[/bold]", result)

        if query:
            flat_query = {key: ", ".join(values) for key, values in query.items()}
            self.show_table("[bold]Parametros da Query[/bold]", flat_query)

        self.pause()

    def steam_public_account_audit(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Raio-X Steam Publico[/bold #4dd0e1]", border_style="#4dd0e1"))
        raw = Prompt.ask("Digite a URL do perfil, custom URL ou SteamID64").strip()

        try:
            base_url = self.normalize_steam_profile_url(raw)
        except ValueError as exc:
            self.show_error(str(exc))
            self.pause()
            return

        try:
            with self.console.status("[bold green]Consultando perfil publico da Steam...[/bold green]"):
                profile_root = ET.fromstring(self.fetch_response(f"{base_url}/?xml=1").text)
                profile_html = self.fetch_response(f"{base_url}/").text
        except requests.RequestException as exc:
            self.show_error(f"Erro ao consultar perfil Steam: {exc}")
            self.pause()
            return
        except ET.ParseError:
            self.show_error("A Steam retornou um XML invalido para esse perfil.")
            self.pause()
            return

        privacy_state = self.xml_text(profile_root, "privacyState")
        visibility_state = self.xml_text(profile_root, "visibilityState")
        state_message = self.clean_steam_text(self.xml_text(profile_root, "stateMessage"))
        steam_status_map = {
            "Online": "Online",
            "Offline": "Offline",
            "In-Game": "Em jogo",
            "Away": "Ausente",
            "Snooze": "Ausente",
            "Busy": "Ocupado",
            "Looking to trade": "Quer trocar",
            "Looking to play": "Quer jogar",
        }
        privacy_map = {"public": "Publico", "private": "Privado", "friendsOnly": "So amigos"}
        visibility_map = {"1": "Privado", "2": "So amigos", "3": "Publico"}
        trade_ban = self.clean_steam_text(self.xml_text(profile_root, "tradeBanState"))

        result = {
            "Nome exibido": self.clean_steam_text(self.xml_text(profile_root, "steamID")),
            "SteamID64": self.xml_text(profile_root, "steamID64"),
            "Custom URL": self.clean_steam_text(self.xml_text(profile_root, "customURL")),
            "Status": steam_status_map.get(state_message, state_message),
            "Privacidade": privacy_map.get(privacy_state, privacy_state),
            "Visibilidade": visibility_map.get(visibility_state, visibility_state),
            "Nivel Steam": self.extract_steam_level(profile_html),
            "Membro desde": self.clean_steam_text(self.xml_text(profile_root, "memberSince")),
            "Nome real": self.clean_steam_text(self.xml_text(profile_root, "realname")),
            "Localizacao": self.clean_steam_text(self.xml_text(profile_root, "location")),
            "VAC ban": "Sim" if self.xml_text(profile_root, "vacBanned", "0") != "0" else "Nao",
            "Trade ban": "Nenhum" if trade_ban == "None" else trade_ban,
            "Conta limitada": "Sim" if self.xml_text(profile_root, "isLimitedAccount", "0") != "0" else "Nao",
            "URL do perfil": base_url,
        }
        self.show_table("[bold]Perfil Steam Publico[/bold]", result)

        summary_text = self.clean_steam_text(self.xml_text(profile_root, "summary"), "")
        if summary_text:
            self.show_panel("[bold]Resumo Publico[/bold]", summary_text, "#ffb347")

        counts = self.extract_steam_profile_counts(profile_html)
        public_counts: dict[str, Any] = {
            "Amigos": counts.get("Friends", "N/D"),
            "Jogos": counts.get("Games", "N/D"),
            "Badges": counts.get("Badges", "N/D"),
            "Premios do perfil": counts.get("Profile Awards", "N/D"),
            "Inventario": counts.get("Inventory", "N/D"),
        }

        friend_counts: dict[str, int] = {}
        friend_names: list[str] = []
        try:
            with self.console.status("[bold green]Consultando amigos e grupos publicos...[/bold green]"):
                friends_html = self.fetch_response(f"{base_url}/friends").text
            friend_counts = self.extract_steam_friend_counts(friends_html)
            friend_names = self.extract_steam_friend_names(friends_html)
        except requests.RequestException:
            pass

        if "cFriends" in friend_counts:
            public_counts["Amigos"] = friend_counts["cFriends"]
        if "cGroups" in friend_counts:
            public_counts["Grupos"] = friend_counts["cGroups"]

        games_info = self.inspect_steam_games_visibility(base_url)
        public_counts["Detalhe da biblioteca"] = games_info["status"]
        self.show_table("[bold]Contadores Publicos[/bold]", public_counts)

        groups = profile_root.findall("./groups/group")
        if groups:
            group_table = Table(title="[bold]Grupos Publicos[/bold]", border_style="#ff5c8a", box=box.SIMPLE_HEAVY)
            group_table.add_column("Grupo", style="#4dd0e1")
            group_table.add_column("Membros", style="white", justify="right")
            group_table.add_column("Online", style="white", justify="right")
            group_table.add_column("Em jogo", style="white", justify="right")
            for group in groups[:8]:
                group_table.add_row(
                    self.safe_terminal_text(self.clean_steam_text(self.xml_text(group, "groupName"))),
                    self.safe_terminal_text(self.xml_text(group, "memberCount")),
                    self.safe_terminal_text(self.xml_text(group, "membersOnline")),
                    self.safe_terminal_text(self.xml_text(group, "membersInGame")),
                )
            self.console.print(group_table)

        if friend_names:
            friend_table = Table(title="[bold]Amostra de Amigos Publicos[/bold]", border_style="#8b5cf6", box=box.SIMPLE_HEAVY)
            friend_table.add_column("#", style="#4dd0e1", justify="right", no_wrap=True)
            friend_table.add_column("Nome", style="white")
            for index, name in enumerate(friend_names, 1):
                friend_table.add_row(self.safe_terminal_text(str(index)), self.safe_terminal_text(name))
            self.console.print(friend_table)

        if games_info["sample"]:
            games_panel = "\n".join(f"- {item}" for item in games_info["sample"])
            self.show_panel("[bold]Amostra de Jogos Publicos[/bold]", games_panel, "#00b894")
        elif games_info["status"] != "Publica":
            self.show_panel(
                "[bold]Visibilidade da Biblioteca[/bold]",
                "A Steam nao expos a lista detalhada de jogos nesse endpoint publico.\n"
                "O contador de jogos do perfil ainda pode aparecer quando ele esta publico.",
                "#ff7aa2",
            )

        if privacy_state.lower() != "public" or visibility_state != "3":
            self.show_panel(
                "[bold]Aviso de Privacidade[/bold]",
                "Esse perfil nao esta totalmente publico. Alguns dados podem ficar escondidos ou truncados.",
                "#ff7aa2",
            )

        self.pause()

    def steam_game_intel(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Intel de Jogo Steam[/bold #4dd0e1]", border_style="#4dd0e1"))
        raw = Prompt.ask("Digite o AppID ou URL da loja Steam").strip()

        try:
            appid = self.normalize_steam_appid(raw)
        except ValueError as exc:
            self.show_error(str(exc))
            self.pause()
            return

        try:
            with self.console.status("[bold green]Consultando detalhes do jogo...[/bold green]"):
                data = self.fetch_steam_app_data(appid)
        except (requests.RequestException, ValueError) as exc:
            self.show_error(f"Erro ao consultar jogo Steam: {exc}")
            self.pause()
            return

        genres = [item.get("description", "N/D") for item in data.get("genres", [])[:6]]
        categories = [item.get("description", "N/D") for item in data.get("categories", [])[:8]]
        recommendations = (data.get("recommendations") or {}).get("total", "N/D")
        dejus = ((data.get("ratings") or {}).get("dejus") or {}).get("rating", "N/D")
        result = {
            "Nome": data.get("name", "N/D"),
            "AppID": data.get("steam_appid", appid),
            "Tipo": data.get("type", "N/D"),
            "Preco": self.format_steam_price(data),
            "Lancamento": (data.get("release_date") or {}).get("date", "N/D"),
            "Desenvolvedora(s)": data.get("developers") or ["N/D"],
            "Publicadora(s)": data.get("publishers") or ["N/D"],
            "Plataformas": self.steam_platforms_text(data.get("platforms")),
            "Generos": genres or ["N/D"],
            "Categorias": categories or ["N/D"],
            "Recomendacoes": recommendations,
            "Conquistas": ((data.get("achievements") or {}).get("total", "N/D")),
            "DLCs": len(data.get("dlc") or []),
            "Classificacao DEJUS": dejus,
            "Site": data.get("website") or "N/D",
        }
        self.show_table("[bold]Intel de Jogo Steam[/bold]", result)

        short_description = self.clean_steam_text(data.get("short_description"), "")
        if short_description:
            self.show_panel("[bold]Descricao Curta[/bold]", short_description, "#00b894")

        notes = self.clean_steam_text(((data.get("content_descriptors") or {}).get("notes")), "")
        if notes:
            self.show_panel("[bold]Aviso de Conteudo[/bold]", notes, "#ff7aa2")

        minimum_pc = self.clean_steam_text(((data.get("pc_requirements") or {}).get("minimum")), "")
        if minimum_pc:
            self.show_panel("[bold]Requisitos Minimos PC[/bold]", minimum_pc, "#8b5cf6")

        self.pause()

    def steam_reviews_snapshot(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Reviews Steam[/bold #4dd0e1]", border_style="#4dd0e1"))
        raw = Prompt.ask("Digite o AppID ou URL da loja Steam").strip()

        try:
            appid = self.normalize_steam_appid(raw)
        except ValueError as exc:
            self.show_error(str(exc))
            self.pause()
            return

        try:
            with self.console.status("[bold green]Consultando reviews...[/bold green]"):
                payload = self.fetch_json(
                    f"https://store.steampowered.com/appreviews/{appid}?json=1&language=all&purchase_type=all&filter=summary&num_per_page=5"
                )
            try:
                app_name = self.fetch_steam_app_data(appid).get("name", f"App {appid}")
            except Exception:
                app_name = f"App {appid}"
        except requests.RequestException as exc:
            self.show_error(f"Erro ao consultar reviews Steam: {exc}")
            self.pause()
            return

        summary = payload.get("query_summary") or {}
        total_reviews = int(summary.get("total_reviews") or 0)
        total_positive = int(summary.get("total_positive") or 0)
        total_negative = int(summary.get("total_negative") or 0)
        approval = round((total_positive / total_reviews) * 100, 2) if total_reviews else 0.0

        result = {
            "Jogo": app_name,
            "AppID": appid,
            "Nota geral": self.steam_review_score_text(summary.get("review_score_desc", "N/D")),
            "Total de reviews": total_reviews,
            "Positivas": total_positive,
            "Negativas": total_negative,
            "Aprovacao": f"{approval}%",
        }
        self.show_table("[bold]Resumo de Reviews Steam[/bold]", result)

        reviews = payload.get("reviews") or []
        if reviews:
            table = Table(title="[bold]Amostra de Reviews[/bold]", border_style="#ffb347", box=box.SIMPLE_HEAVY)
            table.add_column("Autor", style="#4dd0e1")
            table.add_column("Idioma", style="white", no_wrap=True)
            table.add_column("Horas", style="white", justify="right", no_wrap=True)
            table.add_column("Voto", style="white", no_wrap=True)
            table.add_column("Trecho", style="white")
            for review in reviews[:5]:
                author = review.get("author") or {}
                hours = round((author.get("playtime_forever") or 0) / 60, 1)
                snippet = self.trim_text(self.clean_steam_text(review.get("review"), ""), 120)
                table.add_row(
                    self.safe_terminal_text(author.get("personaname", "N/D")),
                    self.safe_terminal_text(review.get("language", "N/D")),
                    self.safe_terminal_text(str(hours)),
                    self.safe_terminal_text("Positiva" if review.get("voted_up") else "Negativa"),
                    self.safe_terminal_text(snippet or "N/D"),
                )
            self.console.print(table)

        self.pause()

    def steam_featured_radar(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Radar de Ofertas Steam[/bold #4dd0e1]", border_style="#4dd0e1"))
        mode = Prompt.ask(
            "Digite O ofertas, D descontos, M mais vendidos, N lancamentos ou E em breve",
            default="O",
        ).strip().upper()
        limit_text = Prompt.ask("Quantos itens listar (1 a 30)", default="10").strip()

        try:
            limit = max(1, min(30, int(limit_text)))
        except ValueError:
            self.show_error("Quantidade invalida.")
            self.pause()
            return

        mode_map = {
            "O": ("specials", "Ofertas Steam"),
            "D": ("specials", "Maiores Descontos Steam"),
            "M": ("top_sellers", "Mais Vendidos Steam"),
            "N": ("new_releases", "Lancamentos Steam"),
            "E": ("coming_soon", "Em Breve na Steam"),
        }
        key, title = mode_map.get(mode, mode_map["O"])

        try:
            with self.console.status("[bold green]Consultando loja Steam...[/bold green]"):
                payload = self.fetch_json("https://store.steampowered.com/api/featuredcategories?cc=br&l=brazilian")
        except requests.RequestException as exc:
            self.show_error(f"Erro ao consultar ofertas Steam: {exc}")
            self.pause()
            return

        items = list(((payload.get(key) or {}).get("items") or []))
        if mode == "D":
            items.sort(key=lambda item: int(item.get("discount_percent") or 0), reverse=True)

        unique_items: list[dict[str, Any]] = []
        seen_ids: set[int] = set()
        for item in items:
            item_id = item.get("id")
            if not isinstance(item_id, int) or item_id in seen_ids:
                continue
            seen_ids.add(item_id)
            unique_items.append(item)
            if len(unique_items) >= limit:
                break

        table = Table(title=f"[bold]{title}[/bold]", border_style="#00b894", box=box.SIMPLE_HEAVY)
        table.add_column("AppID", style="#4dd0e1", justify="right", no_wrap=True)
        table.add_column("Jogo", style="white")
        table.add_column("Preco", style="white", no_wrap=True)
        table.add_column("Desc.", style="white", justify="right", no_wrap=True)
        table.add_column("Obs.", style="white", no_wrap=True)

        links: list[str] = []
        for item in unique_items:
            if item.get("original_price") is None and not item.get("discounted") and (item.get("final_price") or 0) == 0:
                price = "Em breve"
            else:
                price = self.format_price_cents(item.get("final_price"), item.get("currency", "BRL"))
            discount = f"{item.get('discount_percent', 0)}%"
            expiration = self.format_unix_datetime(item.get("discount_expiration")) if item.get("discount_expiration") else "-"
            appid = item.get("id", "N/D")
            game_name = item.get("name", "N/D")
            table.add_row(
                self.safe_terminal_text(appid),
                self.safe_terminal_text(game_name),
                self.safe_terminal_text(price),
                self.safe_terminal_text(discount),
                self.safe_terminal_text(expiration),
            )
            if isinstance(appid, int):
                links.append(f"{self.safe_terminal_text(game_name)} -> {self.steam_store_link(appid)}")
        self.console.print(table)

        if links:
            self.show_panel("[bold]Links das Promocoes[/bold]", "\n".join(links), "#ffb347")

        self.pause()

    def steam_news_feed(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Noticias do Jogo Steam[/bold #4dd0e1]", border_style="#4dd0e1"))
        raw = Prompt.ask("Digite o AppID ou URL da loja Steam").strip()
        count_text = Prompt.ask("Quantas noticias listar", default="5").strip()

        try:
            appid = self.normalize_steam_appid(raw)
            count = max(1, min(10, int(count_text)))
        except ValueError as exc:
            self.show_error(str(exc) if str(exc) else "Entrada invalida.")
            self.pause()
            return

        try:
            with self.console.status("[bold green]Consultando noticias do jogo...[/bold green]"):
                payload = self.fetch_json(
                    f"https://api.steampowered.com/ISteamNews/GetNewsForApp/v2/?appid={appid}&count={count}&maxlength=220&format=json"
                )
            try:
                app_name = self.fetch_steam_app_data(appid).get("name", f"App {appid}")
            except Exception:
                app_name = f"App {appid}"
        except requests.RequestException as exc:
            self.show_error(f"Erro ao consultar noticias Steam: {exc}")
            self.pause()
            return

        items = ((payload.get("appnews") or {}).get("newsitems") or [])
        result = {"Jogo": app_name, "AppID": appid, "Noticias retornadas": len(items)}
        self.show_table("[bold]Feed de Noticias Steam[/bold]", result)

        if items:
            table = Table(title="[bold]Ultimas Noticias[/bold]", border_style="#8b5cf6", box=box.SIMPLE_HEAVY)
            table.add_column("Data", style="#4dd0e1", no_wrap=True)
            table.add_column("Fonte", style="white", no_wrap=True)
            table.add_column("Titulo", style="white")
            table.add_column("Resumo", style="white")
            for item in items:
                table.add_row(
                    self.safe_terminal_text(self.format_unix_datetime(item.get("date"))),
                    self.safe_terminal_text(item.get("feedlabel", "N/D")),
                    self.safe_terminal_text(item.get("title", "N/D")),
                    self.safe_terminal_text(self.trim_text(self.clean_steam_text(item.get("contents"), ""), 110) or "N/D"),
                )
            self.console.print(table)
        else:
            self.show_panel("[bold]Noticias[/bold]", "Nenhuma noticia publica encontrada para esse AppID.", "#ff7aa2")

        self.pause()

    def steam_search_catalog(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Busca de Jogos Steam[/bold #4dd0e1]", border_style="#4dd0e1"))
        term = Prompt.ask("Digite o nome do jogo para buscar").strip()
        limit_text = Prompt.ask("Quantos resultados listar", default="10").strip()

        if not term:
            self.show_error("Digite um termo para buscar.")
            self.pause()
            return

        try:
            limit = max(1, min(20, int(limit_text)))
        except ValueError:
            self.show_error("Quantidade invalida.")
            self.pause()
            return

        try:
            with self.console.status("[bold green]Buscando jogos na Steam...[/bold green]"):
                items = self.fetch_steam_store_search(term)
        except requests.RequestException as exc:
            self.show_error(f"Erro ao buscar jogos Steam: {exc}")
            self.pause()
            return

        table = Table(title="[bold]Resultados da Busca Steam[/bold]", border_style="#00b894", box=box.SIMPLE_HEAVY)
        table.add_column("AppID", style="#4dd0e1", justify="right", no_wrap=True)
        table.add_column("Jogo", style="white")
        table.add_column("Preco", style="white", no_wrap=True)
        table.add_column("Nota", style="white", justify="right", no_wrap=True)
        table.add_column("Plataformas", style="white")

        links: list[str] = []
        for item in items[:limit]:
            price_data = item.get("price") or {}
            if not price_data:
                price = "Gratuito/indefinido"
            else:
                price = self.format_price_cents(price_data.get("final"), price_data.get("currency", "BRL"))
            platforms = self.steam_platforms_text(item.get("platforms"))
            metascore = item.get("metascore") or "-"
            appid = item.get("id", "N/D")
            name = item.get("name", "N/D")
            table.add_row(
                self.safe_terminal_text(appid),
                self.safe_terminal_text(name),
                self.safe_terminal_text(price),
                self.safe_terminal_text(metascore),
                self.safe_terminal_text(platforms),
            )
            if isinstance(appid, int):
                links.append(f"{self.safe_terminal_text(name)} -> {self.steam_store_link(appid)}")

        if not items:
            self.show_panel("[bold]Busca Steam[/bold]", "Nenhum jogo encontrado para esse termo.", "#ff7aa2")
        else:
            self.console.print(table)
            self.show_panel("[bold]Links dos Resultados[/bold]", "\n".join(links[:limit]), "#ffb347")

        self.pause()

    def steam_current_players(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Jogadores Online Steam[/bold #4dd0e1]", border_style="#4dd0e1"))
        raw = Prompt.ask("Digite o AppID ou URL da loja Steam").strip()

        try:
            appid = self.normalize_steam_appid(raw)
        except ValueError as exc:
            self.show_error(str(exc))
            self.pause()
            return

        try:
            with self.console.status("[bold green]Consultando jogadores online...[/bold green]"):
                count = self.fetch_steam_current_player_count(appid)
            try:
                app_name = self.fetch_steam_app_data(appid).get("name", f"App {appid}")
            except Exception:
                app_name = f"App {appid}"
        except requests.RequestException as exc:
            self.show_error(f"Erro ao consultar jogadores online: {exc}")
            self.pause()
            return

        result = {
            "Jogo": app_name,
            "AppID": appid,
            "Jogadores online agora": count if count is not None else "N/D",
            "Link da loja": self.steam_store_link(appid),
        }
        self.show_table("[bold]Jogadores Online Steam[/bold]", result)
        self.pause()

    def steam_compare_games(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Comparador de Jogos Steam[/bold #4dd0e1]", border_style="#4dd0e1"))
        raw_a = Prompt.ask("Primeiro AppID ou URL").strip()
        raw_b = Prompt.ask("Segundo AppID ou URL").strip()

        try:
            appid_a = self.normalize_steam_appid(raw_a)
            appid_b = self.normalize_steam_appid(raw_b)
        except ValueError as exc:
            self.show_error(str(exc))
            self.pause()
            return

        try:
            with self.console.status("[bold green]Comparando jogos...[/bold green]"):
                game_a = self.fetch_steam_app_data(appid_a)
                game_b = self.fetch_steam_app_data(appid_b)
                review_a = self.fetch_steam_review_summary(appid_a)
                review_b = self.fetch_steam_review_summary(appid_b)
                players_a = self.fetch_steam_current_player_count(appid_a)
                players_b = self.fetch_steam_current_player_count(appid_b)
        except (requests.RequestException, ValueError) as exc:
            self.show_error(f"Erro ao comparar jogos Steam: {exc}")
            self.pause()
            return

        table = Table(title="[bold]Comparador Steam[/bold]", border_style="#8b5cf6", box=box.SIMPLE_HEAVY)
        table.add_column("Campo", style="#4dd0e1", no_wrap=True)
        table.add_column(self.safe_terminal_text(game_a.get("name", str(appid_a))), style="white")
        table.add_column(self.safe_terminal_text(game_b.get("name", str(appid_b))), style="white")

        rows = [
            ("AppID", appid_a, appid_b),
            ("Preco", self.format_steam_price(game_a), self.format_steam_price(game_b)),
            ("Lancamento", (game_a.get("release_date") or {}).get("date", "N/D"), (game_b.get("release_date") or {}).get("date", "N/D")),
            ("Plataformas", self.steam_platforms_text(game_a.get("platforms")), self.steam_platforms_text(game_b.get("platforms"))),
            ("Nota reviews", self.steam_review_score_text(review_a.get("review_score_desc", "N/D")), self.steam_review_score_text(review_b.get("review_score_desc", "N/D"))),
            ("Jogadores online", players_a if players_a is not None else "N/D", players_b if players_b is not None else "N/D"),
            ("Recomendacoes", (game_a.get("recommendations") or {}).get("total", "N/D"), (game_b.get("recommendations") or {}).get("total", "N/D")),
            ("Conquistas", (game_a.get("achievements") or {}).get("total", "N/D"), (game_b.get("achievements") or {}).get("total", "N/D")),
            ("Link", self.steam_store_link(appid_a), self.steam_store_link(appid_b)),
        ]
        for field, value_a, value_b in rows:
            table.add_row(
                self.safe_terminal_text(field),
                self.safe_terminal_text(value_a),
                self.safe_terminal_text(value_b),
            )
        self.console.print(table)
        self.pause()

    def steam_dlc_inspector(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Inspetor de DLC Steam[/bold #4dd0e1]", border_style="#4dd0e1"))
        raw = Prompt.ask("Digite o AppID ou URL da loja Steam").strip()
        limit_text = Prompt.ask("Quantas DLCs listar", default="10").strip()

        try:
            appid = self.normalize_steam_appid(raw)
            limit = max(1, min(20, int(limit_text)))
        except ValueError as exc:
            self.show_error(str(exc) if str(exc) else "Entrada invalida.")
            self.pause()
            return

        try:
            with self.console.status("[bold green]Consultando DLCs do jogo...[/bold green]"):
                game = self.fetch_steam_app_data(appid)
                dlc_ids = [int(dlc) for dlc in (game.get("dlc") or [])[:limit] if isinstance(dlc, int)]
                dlc_map = self.fetch_steam_app_batch_data(dlc_ids)
        except (requests.RequestException, ValueError) as exc:
            self.show_error(f"Erro ao consultar DLCs Steam: {exc}")
            self.pause()
            return

        summary = {
            "Jogo base": game.get("name", f"App {appid}"),
            "AppID": appid,
            "Total de DLCs": len(game.get("dlc") or []),
            "DLCs carregadas": len(dlc_map),
            "Link do jogo": self.steam_store_link(appid),
        }
        self.show_table("[bold]Resumo de DLCs[/bold]", summary)

        if not dlc_map:
            self.show_panel("[bold]DLCs[/bold]", "Nenhuma DLC publica encontrada para esse jogo.", "#ff7aa2")
            self.pause()
            return

        table = Table(title="[bold]DLCs Steam[/bold]", border_style="#ffb347", box=box.SIMPLE_HEAVY)
        table.add_column("AppID", style="#4dd0e1", justify="right", no_wrap=True)
        table.add_column("DLC", style="white")
        table.add_column("Preco", style="white", no_wrap=True)
        table.add_column("Lancamento", style="white", no_wrap=True)
        table.add_column("Link", style="white")

        for dlc_appid in dlc_ids:
            data = dlc_map.get(dlc_appid)
            if not data:
                continue
            table.add_row(
                self.safe_terminal_text(dlc_appid),
                self.safe_terminal_text(data.get("name", "N/D")),
                self.safe_terminal_text(self.format_steam_price(data)),
                self.safe_terminal_text((data.get("release_date") or {}).get("date", "N/D")),
                self.safe_terminal_text(self.steam_store_link(dlc_appid)),
            )
        self.console.print(table)
        self.pause()

    def jwt_decoder(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Decodificador JWT[/bold #4dd0e1]", border_style="#4dd0e1"))
        token = Prompt.ask("Cole o JWT").strip()
        parts = token.split(".")

        if len(parts) != 3:
            self.show_error("JWT invalido. Sao esperadas 3 partes.")
            self.pause()
            return

        try:
            header = self.decode_base64url_json(parts[0])
            payload = self.decode_base64url_json(parts[1])
            signature_bytes = len(self.decode_base64url_bytes(parts[2]))

            self.show_panel("[bold]Cabecalho JWT[/bold]", json.dumps(header, indent=2, ensure_ascii=False), "#00b894")
            self.show_panel("[bold]Carga JWT[/bold]", json.dumps(payload, indent=2, ensure_ascii=False), "#4dd0e1")
            self.show_table("[bold]Metadados JWT[/bold]", {"Bytes da assinatura": signature_bytes, "Algoritmo": header.get("alg", "N/D")})
        except Exception as exc:
            self.show_error(f"Falha ao decodificar JWT: {exc}")

        self.pause()

    def hash_text(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Hash de Texto[/bold #4dd0e1]", border_style="#4dd0e1"))
        text = Prompt.ask("Digite o texto para gerar hash")
        encoded = text.encode("utf-8")
        result = {
            "Tamanho": len(text),
            "MD5": hashlib.md5(encoded).hexdigest(),
            "SHA1": hashlib.sha1(encoded).hexdigest(),
            "SHA256": hashlib.sha256(encoded).hexdigest(),
            "SHA512": hashlib.sha512(encoded).hexdigest(),
        }
        self.show_table("[bold]Hashes do Texto[/bold]", result)
        self.pause()

    def hash_file(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Hash de Arquivo[/bold #4dd0e1]", border_style="#4dd0e1"))
        path = Path(Prompt.ask("Digite o caminho do arquivo").strip('\" '))
        if not path.exists() or not path.is_file():
            self.show_error("Arquivo nao encontrado.")
            self.pause()
            return

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()

        try:
            with self.console.status("[bold green]Calculando hashes...[/bold green]"):
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(65536), b""):
                        md5.update(chunk)
                        sha1.update(chunk)
                        sha256.update(chunk)
                        sha512.update(chunk)

            result = {
                "Arquivo": path.name,
                "Caminho": str(path.resolve()),
                "Bytes": path.stat().st_size,
                "MD5": md5.hexdigest(),
                "SHA1": sha1.hexdigest(),
                "SHA256": sha256.hexdigest(),
                "SHA512": sha512.hexdigest(),
            }
            self.show_table("[bold]Hashes do Arquivo[/bold]", result)
        except OSError as exc:
            self.show_error(f"Erro ao ler arquivo: {exc}")

        self.pause()

    def base64_tool(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Laboratorio Base64[/bold #4dd0e1]", border_style="#4dd0e1"))
        mode = Prompt.ask("Digite E para codificar ou D para decodificar", default="E").strip().upper()
        if mode not in {"E", "D"}:
            self.show_error("Modo invalido. Use E ou D.")
            self.pause()
            return
        raw_value = Prompt.ask("Digite o conteudo")

        try:
            if mode == "E":
                result = base64.b64encode(raw_value.encode("utf-8")).decode("utf-8")
                self.show_table("[bold]Resultado Base64[/bold]", {"Modo": "Codificar", "Saida": result})
            else:
                decoded = base64.b64decode(raw_value.encode("utf-8"), validate=True).decode("utf-8")
                self.show_table("[bold]Resultado Base64[/bold]", {"Modo": "Decodificar", "Saida": decoded})
        except Exception as exc:
            self.show_error(f"Falha na operacao Base64: {exc}")

        self.pause()

    def pretty_json(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Laboratorio JSON[/bold #4dd0e1]", border_style="#4dd0e1"))
        self.console.print("[white]Cole um JSON em uma linha e pressione Enter.[/white]")
        raw = input("> ").strip()

        try:
            parsed = json.loads(raw)
            formatted = json.dumps(parsed, indent=2, ensure_ascii=False, sort_keys=True)
            self.show_panel("[bold]JSON Formatado[/bold]", formatted, "#00b894")
        except json.JSONDecodeError as exc:
            self.show_error(f"JSON invalido: {exc}")

        self.pause()

    def regex_tester(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Arena Regex[/bold #4dd0e1]", border_style="#4dd0e1"))
        pattern = Prompt.ask("Digite o regex")
        text = Prompt.ask("Digite o texto para testar")
        flags_raw = Prompt.ask("Flags opcionais (I,M,S) ou Enter", default="")

        flags = 0
        flags_map = {"I": re.IGNORECASE, "M": re.MULTILINE, "S": re.DOTALL}
        for flag_char in flags_raw.upper():
            flags |= flags_map.get(flag_char, 0)

        try:
            compiled = re.compile(pattern, flags)
            matches = compiled.findall(text)
            match_objects = list(compiled.finditer(text))
            result = {
                "Padrao": pattern,
                "Flags": flags_raw.upper() or "nenhuma",
                "Total de matches": len(match_objects),
                "Primeiro match": match_objects[0].group(0) if match_objects else "nenhum",
                "Todos os matches": matches[:10] if matches else ["nenhum"],
            }
            self.show_table("[bold]Relatorio Regex[/bold]", result)
        except re.error as exc:
            self.show_error(f"Regex invalido: {exc}")

        self.pause()

    def text_stats(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Scanner de Texto[/bold #4dd0e1]", border_style="#4dd0e1"))
        self.console.print("[white]Cole o texto em uma linha e pressione Enter.[/white]")
        text = input("> ")
        words = re.findall(r"\b\w+\b", text.lower())
        lines = text.splitlines() or [text]
        result = {
            "Caracteres": len(text),
            "Caracteres sem espacos": len(text.replace(" ", "")),
            "Palavras": len(words),
            "Palavras unicas": len(set(words)),
            "Linhas": len(lines),
            "Digitos": sum(char.isdigit() for char in text),
            "Maiusculas": sum(char.isupper() for char in text),
            "Minusculas": sum(char.islower() for char in text),
            "SHA256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        }
        self.show_table("[bold]Estatisticas do Texto[/bold]", result)
        self.pause()

    def generate_password(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Gerador de Senha[/bold #4dd0e1]", border_style="#4dd0e1"))
        length_text = Prompt.ask("Tamanho da senha", default="18")
        include_symbols = Prompt.ask("Incluir simbolos? (s/n)", choices=["s", "n"], default="s")

        try:
            length = int(length_text)
            if length < 4 or length > 256:
                raise ValueError
        except ValueError:
            self.show_error("Tamanho invalido. Use um numero entre 4 e 256.")
            self.pause()
            return

        alphabet = string.ascii_letters + string.digits
        if include_symbols == "s":
            alphabet += "!@#$%&*?-_+=:;.,"

        password = "".join(secrets.choice(alphabet) for _ in range(length))
        self.show_table(
            "[bold]Senha Gerada[/bold]",
            {
                "Senha": password,
                "Tamanho": length,
                "Simbolos": "sim" if include_symbols == "s" else "nao",
            },
        )
        self.pause()

    def password_strength(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Auditoria de Senha[/bold #4dd0e1]", border_style="#4dd0e1"))
        password = Prompt.ask("Digite a senha para analisar")

        checks = {
            "8+ caracteres": len(password) >= 8,
            "12+ caracteres": len(password) >= 12,
            "minuscula": bool(re.search(r"[a-z]", password)),
            "maiuscula": bool(re.search(r"[A-Z]", password)),
            "digito": bool(re.search(r"\d", password)),
            "simbolo": bool(re.search(r"[^A-Za-z0-9]", password)),
            "sem padrao obvio": not bool(re.search(r"(1234|abcd|senha|password|qwerty|admin)", password, re.IGNORECASE)),
        }

        score = sum(1 for passed in checks.values() if passed)
        if score >= 6:
            level = "forte"
        elif score >= 4:
            level = "media"
        else:
            level = "fraca"

        result = {"Nivel": level, "Pontuacao": f"{score}/{len(checks)}"}
        result.update({name: "OK" if passed else "FALHOU" for name, passed in checks.items()})
        self.show_table("[bold]Auditoria de Senha[/bold]", result)
        self.pause()

    def cpf_tool(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Laboratorio CPF[/bold #4dd0e1]", border_style="#4dd0e1"))
        mode = Prompt.ask("Digite G para gerar ou V para validar", default="G").strip().upper()
        if mode not in {"G", "V"}:
            self.show_error("Modo invalido. Use G ou V.")
            self.pause()
            return

        if mode == "G":
            cpf = self.generate_valid_cpf()
            self.show_table("[bold]CPF Gerado[/bold]", {"CPF": cpf, "Formatado": self.format_cpf(cpf)})
            self.pause()
            return

        cpf = re.sub(r"\D", "", Prompt.ask("Digite o CPF"))
        if len(cpf) != 11:
            self.show_error("CPF invalido. Use 11 digitos.")
            self.pause()
            return

        result = {"CPF": self.format_cpf(cpf), "Valido": "sim" if self.validate_cpf(cpf) else "nao"}
        self.show_table("[bold]Validacao de CPF[/bold]", result)
        self.pause()

    def lookup_cep(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Consulta CEP[/bold #4dd0e1]", border_style="#4dd0e1"))
        cep = re.sub(r"\D", "", Prompt.ask("Digite o CEP").strip())

        if len(cep) != 8:
            self.show_error("CEP invalido. Use 8 digitos.")
            self.pause()
            return

        try:
            with self.console.status("[bold green]Consultando CEP...[/bold green]"):
                data = self.fetch_json(f"https://viacep.com.br/ws/{cep}/json/")

            if data.get("erro"):
                self.show_error("CEP nao encontrado.")
                self.pause()
                return

            result = {
                "CEP": data.get("cep", "N/D"),
                "Logradouro": data.get("logradouro", "N/D"),
                "Complemento": data.get("complemento", "N/D"),
                "Bairro": data.get("bairro", "N/D"),
                "Cidade": data.get("localidade", "N/D"),
                "Estado": data.get("uf", "N/D"),
                "IBGE": data.get("ibge", "N/D"),
            }
            self.show_table("[bold]Consulta de CEP[/bold]", result)
        except requests.RequestException as exc:
            self.show_error(f"Erro de rede: {exc}")

        self.pause()

    def uuid_token_lab(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Laboratorio UUID e Tokens[/bold #4dd0e1]", border_style="#4dd0e1"))
        result = {
            "uuid4": str(uuid.uuid4()),
            "uuid4 hex": uuid.uuid4().hex,
            "token_hex_16": secrets.token_hex(16),
            "token_urlsafe_16": secrets.token_urlsafe(16),
            "segredo_de_sessao": secrets.token_urlsafe(32),
        }
        self.show_table("[bold]Tokens Gerados[/bold]", result)
        self.pause()

    def system_info(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Radar do Sistema[/bold #4dd0e1]", border_style="#4dd0e1"))

        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except OSError:
            hostname = platform.node() or "N/D"
            local_ip = "N/D"

        python_bits = "64-bit" if sys.maxsize > 2**32 else "32-bit"
        total, used, free = shutil.disk_usage(Path.cwd())
        result = {
            "Sistema": platform.system(),
            "Release do sistema": platform.release(),
            "Versao": platform.version(),
            "Arquitetura": platform.machine(),
            "Processador": platform.processor() or "N/D",
            "Hostname": hostname,
            "IP local": local_ip,
            "Python": platform.python_version(),
            "Bits do Python": python_bits,
            "Diretorio atual": str(Path.cwd()),
            "Disco total GB": f"{total / (1024 ** 3):.2f}",
            "Disco livre GB": f"{free / (1024 ** 3):.2f}",
        }
        self.show_table("[bold]Relatorio do Sistema[/bold]", result)

        ping_target = "1.1.1.1"
        ping_cmd = ["ping", "-n" if os.name == "nt" else "-c", "1", ping_target]
        try:
            ping = subprocess.run(
                ping_cmd,
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
            status = "OK" if ping.returncode == 0 else "FAIL"
            output = ping.stdout.strip()[:900] or ping.stderr.strip() or "Sem saida."
            self.show_panel(f"[bold]Teste de Conectividade ({status})[/bold]", output, "#ffb347")
        except Exception as exc:
            self.show_panel("[bold]Teste de Conectividade[/bold]", f"Nao foi possivel executar o ping: {exc}", "#ffb347")

        self.pause()

    def directory_snapshot(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Raio-X do Diretorio[/bold #4dd0e1]", border_style="#4dd0e1"))
        raw_path = Prompt.ask("Digite o diretorio", default=".")
        root = Path(raw_path).expanduser().resolve()

        if not root.exists() or not root.is_dir():
            self.show_error("Diretorio nao encontrado.")
            self.pause()
            return

        total_files = 0
        total_dirs = 0
        total_bytes = 0
        ext_count: dict[str, int] = {}
        biggest: list[tuple[int, str]] = []

        with self.console.status("[bold green]Escaneando diretorio...[/bold green]"):
            for path in root.rglob("*"):
                try:
                    if path.is_dir():
                        total_dirs += 1
                        continue
                    if path.is_file():
                        total_files += 1
                        size = path.stat().st_size
                        total_bytes += size
                        ext = path.suffix.lower() or "[no-ext]"
                        ext_count[ext] = ext_count.get(ext, 0) + 1
                        biggest.append((size, str(path.relative_to(root))))
                except OSError:
                    continue

        biggest.sort(reverse=True)
        top_ext = sorted(ext_count.items(), key=lambda item: (-item[1], item[0]))[:8]
        result = {
            "Raiz": str(root),
            "Diretorios": total_dirs,
            "Arquivos": total_files,
            "Total MB": f"{total_bytes / (1024 ** 2):.2f}",
            "Top extensoes": [f"{ext}: {count}" for ext, count in top_ext] or ["nenhuma"],
            "Maiores arquivos": [f"{size / 1024:.1f} KB - {name}" for size, name in biggest[:6]] or ["nenhum"],
        }
        self.show_table("[bold]Raio-X do Diretorio[/bold]", result)
        self.pause()

    def pc_parts_inspector(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Pecas do PC[/bold #4dd0e1]", border_style="#4dd0e1"))

        cpu_info = self.query_registry_values(r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0")
        bios_info = self.query_registry_values(r"HKLM\HARDWARE\DESCRIPTION\System\BIOS")
        gpu_names = self.query_registry_recursive_value(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}",
            "DriverDesc",
        )
        gpu_versions = self.query_registry_recursive_value(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}",
            "DriverVersion",
        )
        memory = self.get_memory_status()
        mhz = self.registry_dword_to_int(cpu_info.get("~MHz", ""))

        summary = {
            "CPU": cpu_info.get("ProcessorNameString", platform.processor() or "N/D"),
            "Fabricante da CPU": cpu_info.get("VendorIdentifier", "N/D"),
            "Frequencia da CPU MHz": mhz or "N/D",
            "Placa-mae": bios_info.get("BaseBoardProduct", "N/D"),
            "Fabricante da placa": bios_info.get("BaseBoardManufacturer", "N/D"),
            "Fabricante da BIOS": bios_info.get("BIOSVendor", "N/D"),
            "Versao da BIOS": bios_info.get("BIOSVersion", "N/D"),
            "Data da BIOS": bios_info.get("BIOSReleaseDate", "N/D"),
            "Produto do sistema": bios_info.get("SystemProductName", platform.node() or "N/D"),
            "RAM total GB": memory.get("total_gb", "N/D"),
            "RAM livre GB": memory.get("available_gb", "N/D"),
            "Uso de RAM %": memory.get("load_percent", "N/D"),
        }
        self.show_table("[bold]Pecas Principais do PC[/bold]", summary)

        gpu_table = Table(title="[bold]GPU / Video[/bold]", border_style="#ffb347", box=box.SIMPLE_HEAVY)
        gpu_table.add_column("#", style="#4dd0e1", no_wrap=True)
        gpu_table.add_column("Adaptador", style="white")
        gpu_table.add_column("Driver", style="white")
        if gpu_names:
            for index, name in enumerate(gpu_names, start=1):
                driver = gpu_versions[index - 1] if index - 1 < len(gpu_versions) else "N/D"
                gpu_table.add_row(str(index), name, driver)
        else:
            gpu_table.add_row("1", "N/D", "N/D")
        self.console.print(gpu_table)

        drive_table = Table(title="[bold]Mapa de Armazenamento[/bold]", border_style="#8b5cf6", box=box.SIMPLE_HEAVY)
        drive_table.add_column("Unidade", style="#4dd0e1", no_wrap=True)
        drive_table.add_column("Total GB", style="white")
        drive_table.add_column("Livre GB", style="white")
        drive_table.add_column("Uso %", style="white")
        for drive in self.list_windows_drives():
            try:
                total, used, free = shutil.disk_usage(drive)
                used_percent = (used / total * 100) if total else 0
                drive_table.add_row(
                    drive,
                    f"{total / (1024 ** 3):.2f}",
                    f"{free / (1024 ** 3):.2f}",
                    f"{used_percent:.1f}%",
                )
            except OSError:
                continue
        self.console.print(drive_table)
        self.pause()

    def process_snapshot(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Resumo de Processos[/bold #4dd0e1]", border_style="#4dd0e1"))
        top_text = Prompt.ask("Quantos processos listar", default="10")
        try:
            top_n = max(1, min(25, int(top_text)))
        except ValueError:
            self.show_error("Quantidade invalida.")
            self.pause()
            return

        script = (
            "$ErrorActionPreference='SilentlyContinue'; "
            f"Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First {top_n} "
            "ProcessName,Id,CPU,@{Name='MemoryMB';Expression={[math]::Round($_.WorkingSet64/1MB,2)}} "
            "| ConvertTo-Json -Compress"
        )

        try:
            rows = self.run_powershell_json(script)
            if rows is None:
                rows = []
            if isinstance(rows, dict):
                rows = [rows]

            table = Table(title="[bold]Principais Processos[/bold]", border_style="#ff5c8a", box=box.SIMPLE_HEAVY)
            table.add_column("Nome", style="#4dd0e1")
            table.add_column("PID", style="white", no_wrap=True)
            table.add_column("CPU", style="white", no_wrap=True)
            table.add_column("Memoria MB", style="white", no_wrap=True)

            for row in rows:
                cpu_value = row.get("CPU")
                cpu_rendered = f"{float(cpu_value):.2f}" if isinstance(cpu_value, (int, float)) else "N/D"
                table.add_row(
                    str(row.get("ProcessName", "N/D")),
                    str(row.get("Id", "N/D")),
                    cpu_rendered,
                    str(row.get("MemoryMB", "N/D")),
                )
            self.console.print(table)
        except Exception as exc:
            self.show_error(f"Nao foi possivel ler os processos: {exc}")

        self.pause()

    def active_connections(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Conexoes Ativas[/bold #4dd0e1]", border_style="#4dd0e1"))

        process = self.run_command(["netstat", "-ano"], timeout=20)
        if process.returncode != 0:
            self.show_error(process.stderr.strip() or process.stdout.strip() or "Falha ao executar netstat.")
            self.pause()
            return

        parsed: list[dict[str, str]] = []
        state_count: dict[str, int] = {}
        for raw_line in process.stdout.splitlines():
            line = raw_line.strip()
            if not line or not (line.startswith("TCP") or line.startswith("UDP")):
                continue
            parts = re.split(r"\s+", line)
            if parts[0] == "TCP" and len(parts) >= 5:
                proto, local, remote, state, pid = parts[:5]
            elif parts[0] == "UDP" and len(parts) >= 4:
                proto, local, remote, pid = parts[:4]
                state = "SEM_ESTADO"
            else:
                continue
            parsed.append({"proto": proto, "local": local, "remote": remote, "state": state, "pid": pid})
            state_count[state] = state_count.get(state, 0) + 1

        summary = {
            "Total de entradas": len(parsed),
            "Em escuta": state_count.get("LISTENING", 0),
            "Estabelecidas": state_count.get("ESTABLISHED", 0),
            "Aguardando encerramento": state_count.get("TIME_WAIT", 0),
            "Aguardando fechamento": state_count.get("CLOSE_WAIT", 0),
        }
        self.show_table("[bold]Resumo de Conexoes[/bold]", summary)

        table = Table(title="[bold]Fluxo de Conexoes[/bold]", border_style="#00b894", box=box.SIMPLE_HEAVY)
        table.add_column("Proto", style="#4dd0e1", no_wrap=True)
        table.add_column("Local", style="white")
        table.add_column("Remoto", style="white")
        table.add_column("Estado", style="white", no_wrap=True)
        table.add_column("PID", style="white", no_wrap=True)
        for row in parsed[:20]:
            table.add_row(row["proto"], row["local"], row["remote"], row["state"], row["pid"])
        self.console.print(table)
        self.pause()

    def file_entropy_scanner(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Scanner de Entropia[/bold #4dd0e1]", border_style="#4dd0e1"))
        path = Path(Prompt.ask("Digite o caminho do arquivo").strip('" '))
        if not path.exists() or not path.is_file():
            self.show_error("Arquivo nao encontrado.")
            self.pause()
            return

        try:
            data = path.read_bytes()
            entropy = self.calc_entropy(data)
            null_bytes = data.count(0)
            printable = sum(32 <= byte <= 126 or byte in (9, 10, 13) for byte in data)
            printable_ratio = (printable / len(data) * 100) if data else 0

            profile = "Baixa"
            if entropy >= 7.5:
                profile = "Alta / comprimido-ou-criptografado"
            elif entropy >= 5.5:
                profile = "Media / mista"
            elif entropy >= 3.0:
                profile = "Dados legiveis"

            first_bytes = data[:32].hex(" ") if data else ""
            result = {
                "Arquivo": str(path.resolve()),
                "Bytes": len(data),
                "Entropia": f"{entropy:.4f} / 8.0",
                "Perfil": profile,
                "Bytes nulos": null_bytes,
                "Imprimivel %": f"{printable_ratio:.2f}%",
                "SHA256": hashlib.sha256(data).hexdigest(),
                "Primeiros 32 bytes": first_bytes or "vazio",
            }
            self.show_table("[bold]Relatorio de Entropia[/bold]", result)
        except OSError as exc:
            self.show_error(f"Falha ao ler arquivo: {exc}")

        self.pause()

    def duplicate_file_hunter(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Cacador de Duplicados[/bold #4dd0e1]", border_style="#4dd0e1"))
        raw_path = Prompt.ask("Diretorio para scan", default=".")
        limit_text = Prompt.ask("Maximo de arquivos para analisar", default="500")

        try:
            limit = max(10, min(5000, int(limit_text)))
        except ValueError:
            self.show_error("Limite invalido.")
            self.pause()
            return

        root = Path(raw_path).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            self.show_error("Diretorio nao encontrado.")
            self.pause()
            return

        candidates: list[Path] = []
        for path in root.rglob("*"):
            if len(candidates) >= limit:
                break
            try:
                if path.is_file():
                    candidates.append(path)
            except OSError:
                continue

        size_buckets: dict[int, list[Path]] = {}
        for path in candidates:
            try:
                size_buckets.setdefault(path.stat().st_size, []).append(path)
            except OSError:
                continue

        duplicates: dict[str, list[Path]] = {}
        with self.console.status("[bold green]Calculando hashes dos candidatos...[/bold green]"):
            for size, paths in size_buckets.items():
                if len(paths) < 2:
                    continue
                hashed: dict[str, list[Path]] = {}
                for path in paths:
                    try:
                        digest = self.sha256_file(path)
                    except OSError:
                        continue
                    hashed.setdefault(digest, []).append(path)
                for digest, grouped_paths in hashed.items():
                    if len(grouped_paths) > 1:
                        duplicates[digest] = grouped_paths

        summary = {
            "Raiz": str(root),
            "Arquivos analisados": len(candidates),
            "Grupos duplicados": len(duplicates),
            "Arquivos duplicados": sum(len(paths) for paths in duplicates.values()),
        }
        self.show_table("[bold]Resumo de Duplicados[/bold]", summary)

        if duplicates:
            table = Table(title="[bold]Grupos Duplicados[/bold]", border_style="#ffb347", box=box.SIMPLE_HEAVY)
            table.add_column("SHA256", style="#4dd0e1")
            table.add_column("Arquivos", style="white")
            for digest, paths in list(duplicates.items())[:8]:
                rendered_paths = " | ".join(str(path.relative_to(root)) for path in paths[:4])
                if len(paths) > 4:
                    rendered_paths += " | ..."
                table.add_row(digest[:18] + "...", rendered_paths)
            self.console.print(table)

        self.pause()

    def port_range_scanner(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Scanner de Faixa de Portas[/bold #4dd0e1]", border_style="#4dd0e1"))
        host = Prompt.ask("Digite o host ou IP").strip()
        start_text = Prompt.ask("Porta inicial", default="1")
        end_text = Prompt.ask("Porta final", default="1024")

        try:
            start_port = int(start_text)
            end_port = int(end_text)
            if not (1 <= start_port <= end_port <= 65535):
                raise ValueError
            if end_port - start_port > 2048:
                self.show_error("Faixa muito grande. Use no maximo 2048 portas por vez.")
                self.pause()
                return
        except ValueError:
            self.show_error("Faixa de portas invalida.")
            self.pause()
            return

        abertas: list[int] = []
        with self.console.status("[bold green]Escaneando faixa de portas...[/bold green]"):
            for port in range(start_port, end_port + 1):
                try:
                    with socket.create_connection((host, port), timeout=0.25):
                        abertas.append(port)
                except OSError:
                    continue

        result = {
            "Host": host,
            "Porta inicial": start_port,
            "Porta final": end_port,
            "Total de portas abertas": len(abertas),
            "Portas abertas": abertas[:40] or ["nenhuma"],
        }
        self.show_table("[bold]Resultado do Scanner de Portas[/bold]", result)
        self.pause()

    def datetime_converter(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Conversor de Data e Timestamp[/bold #4dd0e1]", border_style="#4dd0e1"))
        modo = Prompt.ask("Digite T para timestamp ou D para data", default="T").strip().upper()
        if modo not in {"T", "D"}:
            self.show_error("Modo invalido. Use T ou D.")
            self.pause()
            return

        if modo == "T":
            raw = Prompt.ask("Digite o timestamp Unix")
            try:
                timestamp = float(raw)
            except ValueError:
                self.show_error("Timestamp invalido.")
                self.pause()
                return

            local_dt = datetime.fromtimestamp(timestamp)
            utc_dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            result = {
                "Timestamp": timestamp,
                "Data local": local_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "Data UTC": utc_dt.strftime("%Y-%m-%d %H:%M:%S %Z"),
                "ISO local": local_dt.isoformat(sep=" "),
                "ISO UTC": utc_dt.isoformat(sep=" "),
            }
            self.show_table("[bold]Conversao de Timestamp[/bold]", result)
            self.pause()
            return

        raw_date = Prompt.ask("Digite a data (YYYY-MM-DD ou YYYY-MM-DD HH:MM:SS)")
        try:
            parsed = self.parse_datetime_value(raw_date)
        except ValueError:
            self.show_error("Data invalida. Use um formato como 2026-03-22 15:30:00.")
            self.pause()
            return

        result = {
            "Data digitada": raw_date,
            "Timestamp local": int(parsed.timestamp()),
            "ISO local": parsed.isoformat(sep=" "),
            "UTC aproximado": parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"),
        }
        self.show_table("[bold]Conversao de Data[/bold]", result)
        self.pause()

    def slug_generator(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Gerador de Slug[/bold #4dd0e1]", border_style="#4dd0e1"))
        texto = Prompt.ask("Digite o texto")
        slug = self.slugify_text(texto)
        snake = slug.replace("-", "_")
        sem_espacos = re.sub(r"\s+", "", texto)
        result = {
            "Texto original": texto,
            "Slug": slug,
            "snake_case": snake,
            "Sem espacos": sem_espacos,
            "MAIUSCULO": slug.upper(),
        }
        self.show_table("[bold]Slug Gerado[/bold]", result)
        self.pause()

    def file_comparator(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Comparador de Arquivos[/bold #4dd0e1]", border_style="#4dd0e1"))
        path_a = Path(Prompt.ask("Primeiro arquivo").strip('" '))
        path_b = Path(Prompt.ask("Segundo arquivo").strip('" '))

        if not path_a.exists() or not path_a.is_file() or not path_b.exists() or not path_b.is_file():
            self.show_error("Um ou mais arquivos nao foram encontrados.")
            self.pause()
            return

        try:
            size_a = path_a.stat().st_size
            size_b = path_b.stat().st_size
            sha_a = self.sha256_file(path_a)
            sha_b = self.sha256_file(path_b)
            iguais = sha_a == sha_b and size_a == size_b
            first_diff = None if iguais else self.first_difference_offset(path_a, path_b)

            result = {
                "Arquivo A": str(path_a.resolve()),
                "Arquivo B": str(path_b.resolve()),
                "Tamanho A": size_a,
                "Tamanho B": size_b,
                "SHA256 A": sha_a,
                "SHA256 B": sha_b,
                "Arquivos iguais": "sim" if iguais else "nao",
                "Primeira diferenca": first_diff if first_diff is not None else "nenhuma",
            }
            self.show_table("[bold]Comparacao de Arquivos[/bold]", result)
        except OSError as exc:
            self.show_error(f"Falha ao comparar arquivos: {exc}")

        self.pause()

    def file_search(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Busca em Arquivos[/bold #4dd0e1]", border_style="#4dd0e1"))
        raw_path = Prompt.ask("Diretorio para busca", default=".")
        termo = Prompt.ask("Texto para buscar").strip()
        extensoes = Prompt.ask("Extensoes separadas por virgula ou Enter para todas", default="").strip()
        limite_texto = Prompt.ask("Maximo de resultados", default="20")

        if not termo:
            self.show_error("Voce precisa informar um texto para buscar.")
            self.pause()
            return

        try:
            limite = max(1, min(200, int(limite_texto)))
        except ValueError:
            self.show_error("Limite invalido.")
            self.pause()
            return

        root = Path(raw_path).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            self.show_error("Diretorio nao encontrado.")
            self.pause()
            return

        extensoes_set = {
            ext.strip().lower() if ext.strip().startswith(".") else f".{ext.strip().lower()}"
            for ext in extensoes.split(",")
            if ext.strip()
        }

        resultados: list[tuple[str, int, str]] = []
        termo_lower = termo.lower()
        with self.console.status("[bold green]Buscando texto nos arquivos...[/bold green]"):
            for path in root.rglob("*"):
                if len(resultados) >= limite:
                    break
                try:
                    if not path.is_file():
                        continue
                    if extensoes_set and path.suffix.lower() not in extensoes_set:
                        continue
                    with path.open("r", encoding="utf-8", errors="ignore") as handle:
                        for numero, linha in enumerate(handle, start=1):
                            if termo_lower in linha.lower():
                                resultados.append((str(path.relative_to(root)), numero, linha.strip()))
                                if len(resultados) >= limite:
                                    break
                except OSError:
                    continue

        resumo = {
            "Diretorio": str(root),
            "Texto buscado": termo,
            "Extensoes": sorted(extensoes_set) if extensoes_set else ["todas"],
            "Resultados": len(resultados),
        }
        self.show_table("[bold]Resumo da Busca[/bold]", resumo)

        if resultados:
            table = Table(title="[bold]Ocorrencias Encontradas[/bold]", border_style="#ff5c8a", box=box.SIMPLE_HEAVY)
            table.add_column("Arquivo", style="#4dd0e1")
            table.add_column("Linha", style="white", no_wrap=True)
            table.add_column("Trecho", style="white")
            for arquivo, linha, trecho in resultados:
                table.add_row(arquivo, str(linha), trecho[:140] or "(linha vazia)")
            self.console.print(table)

        self.pause()

    def csv_summary(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Resumo CSV[/bold #4dd0e1]", border_style="#4dd0e1"))
        path = Path(Prompt.ask("Digite o caminho do arquivo CSV").strip('" '))
        if not path.exists() or not path.is_file():
            self.show_error("Arquivo CSV nao encontrado.")
            self.pause()
            return

        try:
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                sample = handle.read(4096)
                handle.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample or ",")
                except csv.Error:
                    dialect = csv.excel
                reader = csv.reader(handle, dialect)
                rows = list(reader)

            if not rows:
                self.show_error("CSV vazio.")
                self.pause()
                return

            cabecalho = rows[0]
            dados = rows[1:]
            preview = []
            for row in dados[:3]:
                preview.append({cabecalho[i] if i < len(cabecalho) else f"coluna_{i+1}": row[i] for i in range(len(row))})

            result = {
                "Arquivo": str(path.resolve()),
                "Colunas": cabecalho,
                "Total de colunas": len(cabecalho),
                "Total de linhas": len(dados),
                "Amostra": preview or ["sem dados"],
            }
            self.show_table("[bold]Resumo do CSV[/bold]", result)
        except OSError as exc:
            self.show_error(f"Falha ao ler o CSV: {exc}")
        except csv.Error as exc:
            self.show_error(f"CSV invalido: {exc}")

        self.pause()

    def safe_calculator(self) -> None:
        self.console.print(Panel.fit("[bold #4dd0e1]Calculadora Segura[/bold #4dd0e1]", border_style="#4dd0e1"))
        expr = Prompt.ask("Digite a expressao (ex: (2+3)*4**2 - 10/5)")
        try:
            value = self.eval_safe_expr(expr)
            self.show_table("[bold]Resultado da Calculadora[/bold]", {"Expressao": expr, "Resultado": value})
        except Exception as exc:
            self.show_error(f"Expressao invalida: {exc}")

        self.pause()

    def decode_base64url_bytes(self, value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)

    def decode_base64url_json(self, value: str) -> dict[str, Any]:
        return json.loads(self.decode_base64url_bytes(value).decode("utf-8"))

    def generate_valid_cpf(self) -> str:
        digits = [secrets.randbelow(10) for _ in range(9)]
        digits.append(self.cpf_digit(digits, start_weight=10))
        digits.append(self.cpf_digit(digits, start_weight=11))
        return "".join(str(digit) for digit in digits)

    def validate_cpf(self, cpf: str) -> bool:
        cpf = re.sub(r"\D", "", cpf)
        if len(cpf) != 11 or cpf == cpf[0] * 11:
            return False
        numbers = [int(char) for char in cpf]
        return (
            numbers[9] == self.cpf_digit(numbers[:9], start_weight=10)
            and numbers[10] == self.cpf_digit(numbers[:10], start_weight=11)
        )

    @staticmethod
    def cpf_digit(numbers: list[int], start_weight: int) -> int:
        total = sum(number * weight for number, weight in zip(numbers, range(start_weight, 1, -1)))
        remainder = (total * 10) % 11
        return 0 if remainder == 10 else remainder

    @staticmethod
    def format_cpf(cpf: str) -> str:
        clean = re.sub(r"\D", "", cpf)
        return f"{clean[:3]}.{clean[3:6]}.{clean[6:9]}-{clean[9:]}"

    def eval_safe_expr(self, expression: str) -> float | int:
        allowed_binops = {
            ast.Add: lambda a, b: a + b,
            ast.Sub: lambda a, b: a - b,
            ast.Mult: lambda a, b: a * b,
            ast.Div: lambda a, b: a / b,
            ast.FloorDiv: lambda a, b: a // b,
            ast.Mod: lambda a, b: a % b,
            ast.Pow: lambda a, b: a**b,
        }
        allowed_unary = {
            ast.UAdd: lambda a: +a,
            ast.USub: lambda a: -a,
        }

        def visit(node: ast.AST) -> float | int:
            if isinstance(node, ast.Expression):
                return visit(node.body)
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return node.value
            if isinstance(node, ast.BinOp) and type(node.op) in allowed_binops:
                return allowed_binops[type(node.op)](visit(node.left), visit(node.right))
            if isinstance(node, ast.UnaryOp) and type(node.op) in allowed_unary:
                return allowed_unary[type(node.op)](visit(node.operand))
            raise ValueError("Apenas numeros, parenteses e operadores matematicos simples sao permitidos.")

        tree = ast.parse(expression, mode="eval")
        return visit(tree)


def main() -> None:
    app = SkullToolbox()
    app.run()


if __name__ == "__main__":
    main()
