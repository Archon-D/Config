#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
surge2singbox —— 把 Surge / Clash / 纯域名 / sing-box 规则列表转换成 sing-box rule-set。

用法：
    python3 Rule_Convert.py                       # 读 ./RulesList.txt，产物写到 ./out
    python3 Rule_Convert.py --singbox bin/sing-box --jobs 8 --out out
    python3 Rule_Convert.py --no-compile          # 只出 json，不调 sing-box
    python3 Rule_Convert.py --names modern        # 换成 skk_/owner_ 前缀的新命名

默认读 <脚本目录>/RulesList.txt，产物写 <脚本目录>/Rules/；--names legacy（默认）
沿用原脚本的 basename 文件名与 _ip_cidr 后缀，便于直接替换旧脚本。
    python3 -m unittest discover -s tests    # 离线单元测试

行为要点：
  * 纯标准库（无 pandas / pyyaml / requests），逐行解析：逗号规则 / 裸域名 / .suffix /
    *.wildcard / payload 列表 / 已有 rule-set JSON 都能吃。
  * 一个源 = 一个集合：域名、IP、进程、端口全写进同一个 rule-set（默认）。
    加 --split-ip 才会按"域名类 / IP 类"拆成两个文件（DNS 阶段只想用域名规则时才有必要）。
  * 重名在转换前统一处理：同名（basename 相同）的源**全部**加上 URL 上一级目录前缀，
    domainset/cdn.conf + non_ip/cdn.conf -> domainset_cdn + non_ip_cdn，不挑谁留下。
  * skk 在每个组里塞的演练域名 7h15.ru1353t...skk.moe 默认排除（--exclude-domain 可加更多）。
  * URL-REGEX 降级为域名正则并留在原集合（--separate-url-regex 可拆出去）；
    每次降级记 lossy，不算丢弃。
  * 不静默失败：抓取失败、无法转换的类型、非法的值全部记录到 <name>.dropped.txt 和 report.json；
    编译后回读 .srs 逐项校验。有链接失败退出码 1，--strict 时有真丢弃也退出 1。
  * 输出确定（列表排序去重），同名不同源不会互相覆盖。
"""
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import urlsplit

# 默认路径相对脚本自身，而不是 CWD —— 在 CI 里怎么 cd 都不会错
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_RULES_LIST = SCRIPT_DIR / "RulesList.txt"
DEFAULT_OUT = SCRIPT_DIR / "Rules"

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# 类型映射表
# ---------------------------------------------------------------------------
# 值：
#   "domain" / "domain_suffix" / ...  直接落成该 item
#   WILDCARD   需要转成正则
#   URL_REGEX  需要专门处理（sing-box 无法匹配 URL）
#   UNSUPPORTED sing-box rule-set 没有对应 item
TYPE_MAP: dict[str, str] = {
    # 域名
    "DOMAIN": "domain", "HOST": "domain", "domain": "domain",
    "DOMAIN-SUFFIX": "domain_suffix", "HOST-SUFFIX": "domain_suffix",
    "domain_suffix": "domain_suffix", "DOMAIN-SET": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword", "HOST-KEYWORD": "domain_keyword",
    "domain_keyword": "domain_keyword",
    "DOMAIN-REGEX": "domain_regex", "domain_regex": "domain_regex",
    "DOMAIN-WILDCARD": "__wildcard__",
    "URL-REGEX": "__url_regex__",
    # IP
    "IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr", "IP6-CIDR": "ip_cidr",
    "ip_cidr": "ip_cidr", "SRC-IP-CIDR": "source_ip_cidr",
    "source_ip_cidr": "source_ip_cidr",
    # 端口
    "DST-PORT": "port", "DEST-PORT": "port", "port": "port",
    "SRC-PORT": "source_port", "SOURCE-PORT": "source_port",
    "source_port": "source_port",
    # 进程
    "PROCESS-NAME": "process_name", "process_name": "process_name",
    "PROCESS-PATH": "process_path", "process_path": "process_path",
    # 无对应 item
    "USER-AGENT": "__unsupported__", "IP-ASN": "__unsupported__",
    "GEOIP": "__unsupported__", "RULE-SET": "__unsupported__",
    "FINAL": "__unsupported__", "MATCH": "__unsupported__",
    "AND": "__unsupported__", "OR": "__unsupported__", "NOT": "__unsupported__",
    "SCRIPT": "__unsupported__", "CELLULAR-RADIO": "__unsupported__",
    "PROTOCOL": "__unsupported__", "DEVICE-NAME": "__unsupported__",
}

# 输出时 item 的固定顺序，保证确定性
ITEM_ORDER = [
    "domain", "domain_suffix", "domain_keyword", "domain_regex",
    "ip_cidr", "source_ip_cidr",
    "process_name", "process_path", "package_name",
    "port", "port_range", "source_port", "source_port_range",
]
IP_ITEMS = {"ip_cidr", "source_ip_cidr"}

# 同一个规则对象里的不同"匹配维度"之间是 AND（实测：域名 + process_name 永远不命中），
# 所以每个维度必须单独成一个对象，对象之间才是 OR。四个域名类字段彼此是 OR，可以合并。
ITEM_GROUPS: list[tuple[str, ...]] = [
    ("domain", "domain_suffix", "domain_keyword", "domain_regex"),
    ("ip_cidr",),
    ("source_ip_cidr",),
    ("process_name",),
    ("process_path",),
    ("package_name",),
    ("port", "port_range"),
    ("source_port", "source_port_range"),
]
DOMAIN_ITEMS = {"domain", "domain_suffix", "domain_keyword", "domain_regex"}

# skk 在每个规则组里塞的"水印"域名（纯 IP 组也有），对分流没有意义，还会把纯 IP 组
# 污染成"域名 + IP"混合组。实测同一批文件里就有 5 种写法：
#   7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe / 7h15_ru1353t_...（下划线版）
#   7h1s_rul35et_i5_mad3_by_5ukk4w-ruleset.skk.moe / th1s_rule5et_1s_m4d3_by_....
#   this_ruleset_is_made_by_sukkaw.ruleset.skk.moe
# 它们全都在 skk.moe 下，所以直接按域名后缀识别，作者以后换措辞也兜得住。
PLACEHOLDER_DOMAINS = {
    "7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe",
    "7h15_ru1353t_1s_m4d3_by_5ukk4w.skk.moe",
}
# 用"整段标签命中"而不是子串匹配，免得误伤 health1st.com 这类真域名。
# 注意不能按 *.skk.moe 整体排除：ruleset.skk.moe、cdn.skk.moe、latency-test.skk.moe
# 这些是规则集的镜像/测速节点，是真正的规则。
PLACEHOLDER_LABELS = {
    "7h15", "7h1s", "th1s", "5ukk4w", "sukkaw", "m4d3", "mad3", "rul35et", "rule5et",
}


def is_placeholder(domain: str) -> bool:
    if domain in PLACEHOLDER_DOMAINS:
        return True
    return any(label in PLACEHOLDER_LABELS for label in re.split(r"[._-]", domain))

COMMENT_PREFIX = ("#", "//", ";", "!")
# 从 URL 路径里剥掉的噪音目录
NOISE_SEGMENTS = {
    "rule", "rules", "surge", "list", "lists", "refs", "heads",
    "master", "main", "config", "ios_rule_script", "List",
}
ANDROID_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")


# ---------------------------------------------------------------------------
# 抓取
# ---------------------------------------------------------------------------
def fetch_text(url: str, timeout: float, retries: int) -> str:
    """抓取文本；支持 http(s)、file:// 和本地路径。失败抛 RuntimeError。"""
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            if url.startswith(("http://", "https://")):
                req = urllib.request.Request(
                    url, headers={"User-Agent": USER_AGENT, "Accept": "text/plain,*/*"}
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status = getattr(resp, "status", 200)
                    if status != 200:
                        raise RuntimeError(f"HTTP {status}")
                    return resp.read().decode("utf-8-sig", "replace")
            path = url[7:] if url.startswith("file://") else url
            return Path(path).read_text(encoding="utf-8-sig", errors="replace")
        except Exception as exc:  # 这里必须捕，但错误会往上抛，不吞
            last = exc
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"{type(last).__name__}: {last}")


# ---------------------------------------------------------------------------
# 单条规则的归一化
# ---------------------------------------------------------------------------
_WILDCARD_ESCAPE = re.compile(r"([.^$+{}\[\]\\|()])")


def glob_to_regex(pattern: str, single_label: bool = False) -> str:
    """Surge DOMAIN-WILDCARD -> sing-box domain_regex。

    Surge 官方语义（manual.nssurge.com/rules/domain.html）：`*` 匹配任意个字符
    （含零个）且**跨过点**，`?` 匹配一个字符，支持 `[...]` 字符组。
    所以默认 `*` -> `.*`；`single_label=True` 时退化成 `[^.]*`（只吃一个 label）。
    """
    star = "[^.]*" if single_label else ".*"
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            out.append(star)
            i += 1
        elif ch == "?":
            out.append(".")
            i += 1
        elif ch == "[":
            end = pattern.find("]", i + 1)
            if end == -1:                      # 未闭合的 [ 当字面量
                out.append(r"\[")
                i += 1
                continue
            body = pattern[i + 1:end]
            if body.startswith("!"):           # Surge/glob 的取反写法
                body = "^" + body[1:]
            elif body.startswith("^"):         # 字面量 ^，别让正则当成取反
                body = "\\" + body
            out.append("[" + body + "]")
            i = end + 1
        else:
            out.append(_WILDCARD_ESCAPE.sub(r"\\\1", ch))
            i += 1
    return "^" + "".join(out) + "$"


SCHEME_RE = re.compile(r"^(?:\(?https?\??\)?|\(?wss?\??\)?):(?:\/{0,2})", re.I)


def url_regex_to_domain(expr: str) -> str | None:
    r"""
    URL 正则 -> 域名正则（有损：路径部分丢掉，匹配范围变宽）。

    做法：去掉锚点和 scheme，取到第一个 '/' 之前的部分当作 host 正则，两端加 ^$。
    host 段本来就是正则（如 `(.+)\.gvt\d\.com`），原样保留交给 Go RE2 匹配。
    """
    s = expr.strip()
    s = re.sub(r"\\/", "/", s)              # \/ -> /
    s = s.lstrip("^")
    s = SCHEME_RE.sub("", s, count=1).lstrip("/")
    s = re.split(r"(?<!\\)/", s, maxsplit=1)[0]   # 取 host 段
    s = s.rstrip(".")
    if not s or "$" in s or "^" in s or "//" in s:
        return None
    # 挡掉"什么都能匹配"的退化正则：.* 或 [^/]+ 之类去掉元字符后什么都不剩，
    # 拿它当域名正则会把全部域名都命中，比不转换危险得多。
    probe = s.replace("\\.", ".")
    probe = re.sub(r"\\[A-Za-z]", "", probe)
    probe = re.sub(r"[\[\](){}^$*+?|/]", "", probe)
    if "." not in probe or len(re.sub(r"[^A-Za-z0-9.-]", "", probe)) < 3:
        return None
    try:
        re.compile("^" + s + "$")            # 先用 Python 的 re 挡掉明显的语法错
    except re.error:
        return None
    return "^" + s + "$"


def normalize_domain(value: str) -> str | None:
    v = value.strip().strip("'\"").strip()
    v = re.sub(r"^[a-z]+://", "", v, flags=re.I).split("/", 1)[0]
    # 各家的前缀写法：+.example.com / .example.com / example.com.
    v = v.strip().lstrip("+.").rstrip(".").lower()
    if not v or len(v) > 253:
        return None
    if any(c in v for c in " \t,;/*?=@\"'"):
        return None
    if not v.isascii():            # IDN -> punycode
        try:
            v = v.encode("idna").decode("ascii")
        except Exception:
            return None
    labels = v.split(".")
    if any(not lab or len(lab) > 63 for lab in labels):
        return None
    if not re.fullmatch(r"[a-z0-9._\-]+", v):
        return None
    return v


def normalize_cidr(value: str) -> str | None:
    v = value.strip().strip("'\"").strip()
    try:
        return str(ipaddress.ip_network(v, strict=False))
    except ValueError:
        return None


def normalize_port(value: str) -> tuple[str, str] | None:
    v = value.strip().strip("'\"")
    if not v:
        return None
    if ":" in v or "-" in v:
        parts = re.split(r"[:-]", v, maxsplit=1)
        try:
            lo, hi = int(parts[0]), int(parts[1])
        except (ValueError, IndexError):
            return None
        if not (0 < lo <= hi <= 65535):
            return None
        return "port_range", f"{lo}:{hi}"
    try:
        p = int(v)
    except ValueError:
        return None
    if not (0 < p <= 65535):
        return None
    return "port", str(p)


# ---------------------------------------------------------------------------
# 转换统计
# ---------------------------------------------------------------------------
@dataclass
class SetBuilder:
    """收集一条链接里的所有规则。"""

    rule_version: int = 2
    wildcard_single_label: bool = False
    url_regex_mode: str = "host"
    items: dict[str, set[str]] = field(default_factory=lambda: {k: set() for k in ITEM_ORDER})
    excluded: set[str] = field(default_factory=lambda: set(PLACEHOLDER_DOMAINS))
    extra_excluded: Iterable[str] = ()      # --exclude-domain 追加的（已归一化）
    dropped: list[tuple[str, str]] = field(default_factory=list)   # (reason, raw)
    url_regex_items: set[str] = field(default_factory=set)         # URL-REGEX 降级出来的项
    parsed: int = 0      # 读到的规则条数
    consumed: int = 0    # 至少产出一条 item 的条数
    _line_hit: bool = False

    # -- 收集 ------------------------------------------------------------
    def _add(self, item: str, value: str) -> None:
        # 占位/演练域名：既不是真规则，也不该让纯 IP 组变成混合组
        if item in ("domain", "domain_suffix") and (
            is_placeholder(value) or value in self.excluded or value in self.extra_excluded
        ):
            self._drop("excluded:placeholder-domain", f"{item}:{value}")
            return
        self._line_hit = True
        self.items[item].add(value)

    def _drop(self, reason: str, raw: str) -> None:
        self.dropped.append((reason, raw[:300]))

    def add_rule(self, raw: str, rtype: str, payload: str) -> None:
        """rtype 是原始类型名，payload 是逗号后的第一个字段。"""
        self.parsed += 1
        self._line_hit = False
        self._dispatch(raw, rtype, payload)
        self.consumed += self._line_hit

    def _dispatch(self, raw: str, rtype: str, payload: str) -> None:
        item = TYPE_MAP.get(rtype) or TYPE_MAP.get(rtype.upper())

        if item is None:
            # 没见过的类型：可能是裸域名被误判成 "type,value"
            self._drop(f"unknown-type:{rtype}", raw)
            return

        if item == "__unsupported__":
            self._drop(f"unsupported:{rtype.upper()}", raw)
            return

        if item == "__url_regex__":
            if self.url_regex_mode == "drop":
                self._drop("unsupported:URL-REGEX", raw)
                return
            conv = url_regex_to_domain(payload)
            if conv:
                self._add("domain_regex", conv)
                self.url_regex_items.add(conv)
                # lossy 前缀 = 已保留但语义变宽，单独计数，不算真丢弃
                self._drop("lossy:URL-REGEX->domain_regex", raw)
            else:
                self._drop("unsupported:URL-REGEX(cannot-reduce)", raw)
            return

        if item == "__wildcard__":
            dom = payload.strip().strip("'\"")
            if not dom:
                self._drop("invalid:empty", raw)
                return
            self._add("domain_regex", glob_to_regex(dom.lower(), self.wildcard_single_label))
            return

        if item == "ip_cidr" or item == "source_ip_cidr":
            cidr = normalize_cidr(payload)
            if cidr is None:
                self._drop(f"invalid:{item}", raw)
            else:
                self._add(item, cidr)
            return

        if item in ("port", "source_port"):
            got = normalize_port(payload)
            if got is None:
                self._drop(f"invalid:{item}", raw)
                return
            kind, val = got
            if item == "source_port":                 # 源端口别落进 port
                kind = "source_port_range" if kind == "port_range" else "source_port"
            self._add(kind, val)
            return

        if item == "domain_regex":
            regex = payload.strip().strip("'\"")
            if regex:
                self._add("domain_regex", regex)
            else:
                self._drop("invalid:domain_regex", raw)
            return

        if item in ("process_name", "process_path"):
            name = payload.strip().strip("'\"")
            if not name:
                self._drop(f"invalid:{item}", raw)
                return
            self._add(item, name)
            # Android App ID 形态同时给 package_name，跨平台都能命中
            if item == "process_name" and ANDROID_ID_RE.match(name):
                self._add("package_name", name)
            return

        # 剩下的都是域名类
        dom = normalize_domain(payload)
        if dom is None:
            self._drop(f"invalid:{item}", raw)
        else:
            self._add(item, dom)

    def add_bare(self, token: str) -> None:
        """无逗号的裸条目：按内容推断。"""
        self.parsed += 1
        self._line_hit = False
        self._dispatch_bare(token)
        self.consumed += self._line_hit

    def _dispatch_bare(self, token: str) -> None:
        v = token.strip().strip("'\"").strip()
        if not v:
            return
        if v[0] in "+.":
            dom = normalize_domain(v.lstrip("+."))
            if dom:
                self._add("domain_suffix", dom)
            else:
                self._drop("invalid:domain_suffix", token)
            return
        if "*" in v or "?" in v:
            self._add("domain_regex", glob_to_regex(v.lower(), self.wildcard_single_label))
            return
        if "/" in v:
            cidr = normalize_cidr(v)
            if cidr:
                self._add("ip_cidr", cidr)
            else:
                self._drop("invalid:ip_cidr", token)
            return
        try:
            ipaddress.ip_address(v)
        except ValueError:
            dom = normalize_domain(v)
            if dom:
                self._add("domain", dom)     # 裸域名 = 精确匹配（与 skk 官方 sing-box 输出一致）
            else:
                self._drop("invalid:domain", token)
            return
        self._add("ip_cidr", str(ipaddress.ip_network(v, strict=False)))

    # -- 输出 ------------------------------------------------------------
    def has(self, items: Iterable[str]) -> bool:
        return any(self.items[i] for i in items)

    def build(
        self,
        items: Iterable[str],
        only: frozenset[str] | set[str] | None = None,
        drop: frozenset[str] | set[str] = frozenset(),
    ) -> dict:
        """
        items：要哪些 item 字段；only/drop：对取值再筛一层。

        一个维度一个规则对象：对象内部是 AND，对象之间是 OR。
        同一对象里塞域名 + process_name 会让整条规则永远不命中（sing-box 用进程名做
        额外条件），所以按 ITEM_GROUPS 拆开，集合内部的语义才是"任一命中即算"。
        """
        allowed = set(items)
        rules: list[dict] = []
        for group in ITEM_GROUPS:
            rule: dict[str, list] = {}
            for key in group:
                if key not in allowed or not self.items[key]:
                    continue
                vals = self.items[key]
                if only is not None:
                    vals = vals & only
                elif drop:
                    vals = vals - drop
                if not vals:
                    continue
                if key in ("port", "source_port"):
                    rule[key] = sorted(int(v) for v in vals)   # sing-box 要求 uint16
                else:
                    rule[key] = sorted(vals)
            if rule:
                rules.append(rule)
        return {"version": self.rule_version, "rules": rules}


# ---------------------------------------------------------------------------
# 解析文档
# ---------------------------------------------------------------------------
def iter_rule_tokens(text: str) -> Iterator[str]:
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith(COMMENT_PREFIX):
            continue
        if line.startswith("- "):                     # Clash YAML 列表项
            line = line[2:].strip().strip("'\"")
        if line in ("payload:", "rules:", "rule:") or line.endswith(":") and "," not in line:
            continue
        if not line:
            continue
        yield line


def parse_document(text: str, builder: SetBuilder) -> None:
    """识别文档格式并灌进 builder。"""
    stripped = text.lstrip()
    if stripped.startswith("{"):
        # sing-box rule-set JSON：直接合并 item，方便链式转换
        try:
            doc = json.loads(stripped)
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, dict) and isinstance(doc.get("rules"), list):
            for rule in doc["rules"]:
                if not isinstance(rule, dict):
                    continue
                for key, val in rule.items():
                    if key in builder.items:
                        for v in val if isinstance(val, list) else [val]:
                            builder.items[key].add(str(v))
                        builder.parsed += 1
                    else:
                        builder._drop(f"unsupported:ruleset-item:{key}", json.dumps(rule))
            return

    for line in iter_rule_tokens(text):
        if "," in line:
            rtype, rest = line.split(",", 1)
            # 一行可能是 "DOMAIN-SUFFIX,google.com,no-resolve"，只要第一段
            payload = rest.split(",", 1)[0]
            builder.add_rule(line, rtype.strip(), payload.strip())
        else:
            builder.add_bare(line)


# ---------------------------------------------------------------------------
# 命名
# ---------------------------------------------------------------------------
EXT_RE = re.compile(r"\.(list|json|conf|txt|yaml|yml|dat)$", re.I)


def legacy_name(url: str) -> str:
    """原脚本的命名：basename(link).split('.')[0]。--names legacy 用它保持文件名不变。"""
    return url.split("/")[-1].split(".")[0] or "set"


def derive_name(url: str) -> str:
    """skk + 路径 -> skk_domainset_reject；owner + 路径 -> blackmatrix7_Google。"""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    segs = [s for s in parts.path.split("/") if s]
    noise = {n.lower() for n in NOISE_SEGMENTS}

    if not host:                    # 本地文件：只用文件名
        return _sanitize(EXT_RE.sub("", segs[-1]) if segs else "set")
    if host.endswith("skk.moe"):
        prefix = "skk"
    elif host in ("raw.githubusercontent.com", "github.com", "gitee.com"):
        prefix = segs[0] if segs else "gh"
        segs = segs[1:]
        if len(segs) >= 2:          # 去掉 repo 和 ref
            segs = segs[2:]
    elif host:
        prefix = host.split(".")[0]
    else:
        prefix = "local"

    kept = [s for s in segs if s.lower() not in noise] or segs or ["set"]
    last = kept[-1]
    stem = EXT_RE.sub("", last)
    dirs = [d for d in kept[:-1] if d.lower() not in (stem.lower(), prefix.lower())]

    return _sanitize("_".join([prefix] + dirs + [stem]))


def _sanitize(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-_.-") or "set"


def path_token(url: str) -> str:
    """URL 里能区分同名的路径段：domainset/cdn.conf -> domainset。"""
    segs = [s for s in urlsplit(url).path.split("/") if s]
    noise = {n.lower() for n in NOISE_SEGMENTS}
    dirs = [s for s in segs[:-1] if s.lower() not in noise]
    return _sanitize(dirs[-1]) if dirs else "dup"


def resolve_names(
    urls: list[str],
    mode: str = "legacy",
    split_ip: bool = False,
    separate_url_regex: bool = False,
) -> list[tuple[str, str]]:
    """
    在下拉/转换之前就把产物名定好，重名一律加 URL 的上一级目录前缀来区分。

    legacy（默认，与原脚本一致）：basename 前段，如 reject.conf -> reject。
    撞名时**所有**同名的源都加前缀，不挑"谁留下"：
        domainset/cdn.conf + non_ip/cdn.conf
            -> domainset_cdn + non_ip_cdn
    这样名字是对称的，也不会出现"某次运行后 cdn.json 悄悄换了个源"。
    """
    namer = legacy_name if mode == "legacy" else derive_name
    plan = [(url, namer(url)) for url in urls]
    ip_suffix = "_ip_cidr" if mode == "legacy" else "_ip"

    def variants(name: str) -> set[str]:
        """一个源可能写出的全部文件名（主集合 + 拆分出来的 + 可选的正则集合）。"""
        out = {name}
        if split_ip:
            out |= {f"{name}{ip_suffix}", f"{name}_domain"}
        if separate_url_regex:
            out.add(f"{name}_url_regex")
        return out

    grouped: dict[str, list[int]] = {}
    for i, (_, name) in enumerate(plan):
        grouped.setdefault(name, []).append(i)

    # 第一层：同 basename 的源，全部加路径段前缀
    for name, idxs in grouped.items():
        if len(idxs) < 2:
            continue
        print(f"检测到重名：{name}（{len(idxs)} 个源），全部加 URL 上一级目录区分：",
              file=sys.stderr)
        for i in idxs:
            url = plan[i][0]
            base, n = f"{path_token(url)}_{name}", 2
            while base == name or base in grouped:
                base, n = f"{path_token(url)}_{name}-{n}", n + 1
            plan[i] = (url, base)
            print(f"  {url}\n      -> {base}.json", file=sys.stderr)

    # 第二层：派生名也不能撞。比如 A 会写出 foo_ip_cidr，而 RulesList 里恰好还有个
    # foo_ip_cidr.conf，两者会在磁盘上互相覆盖（并发下连谁赢都不确定）。
    # 按列表顺序预留名字，撞了就整源改名，保证一个产物文件只属于一个源。
    reserved: set[str] = set()
    all_names = {name for _, name in plan}
    for i, (url, name) in enumerate(plan):
        if variants(name) & reserved:
            base, n = f"{path_token(url)}_{name}", 2
            while (variants(base) & reserved) or (base in all_names and base != name):
                base, n = f"{path_token(url)}_{name}-{n}", n + 1
            print(f"派生名冲突：{url}\n          -> {base}（否则会与其它源的 *_ip/_domain 撞名）",
                  file=sys.stderr)
            plan[i] = (url, base)
        reserved |= variants(plan[i][1])
    return plan


# ---------------------------------------------------------------------------
# 单条链接的处理
# ---------------------------------------------------------------------------
@dataclass
class Result:
    url: str
    name: str
    ok: bool
    error: str = ""
    parsed: int = 0
    kept: int = 0
    counts: dict[str, int] = field(default_factory=dict)        # 主文件
    parts: dict[str, dict[str, int]] = field(default_factory=dict)  # 每个产物文件的条数
    dropped: dict[str, int] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    json_bytes: int = 0
    srs_bytes: int = 0
    seconds: float = 0.0
    merged_ip: int = 0
    lossy: int = 0          # 已保留但语义变宽（URL-REGEX 降级）
    skipped: bool = False   # 解析出来 0 条可用规则（如纯 IP-ASN 源）
    warning: str = ""


def compile_rule_set(singbox: str, src: Path, dst: Path) -> None:
    proc = subprocess.run(
        [singbox, "rule-set", "compile", "-o", str(dst), str(src)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"sing-box compile 失败: {(proc.stderr or proc.stdout).strip()[:300]}")
    if not dst.exists() or dst.stat().st_size == 0:
        raise RuntimeError("sing-box compile 没产生 .srs")


def _collect_items(doc: dict) -> dict[str, list[str]]:
    """decompile 出来单元素列表会退化成标量，这里统一成列表。"""
    got: dict[str, list[str]] = {}
    for rule in doc.get("rules", []):
        for key, val in rule.items():
            vals = val if isinstance(val, list) else [val]
            got.setdefault(key, []).extend(str(v) for v in vals)
    return got


def verify_rule_set(singbox: str, srs: Path, expected: dict[str, list]) -> int:
    """回读 .srs，确认规则没有在编译阶段丢失。返回被编译器合并掉的 CIDR 条数。"""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    merged = 0
    try:
        proc = subprocess.run(
            [singbox, "rule-set", "decompile", "-o", str(tmp_path), str(srs)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"sing-box decompile 失败: {(proc.stderr or proc.stdout).strip()[:300]}")
        got = _collect_items(json.loads(tmp_path.read_text()))
    finally:
        tmp_path.unlink(missing_ok=True)

    for key, want in expected.items():
        have = got.get(key, [])
        if key in IP_ITEMS:
            # 编译器会把相邻/被包含的网段合并，语义不变，所以校验覆盖而不是逐条相等
            try:
                nets = [ipaddress.ip_network(str(v), strict=False) for v in have]
            except ValueError as exc:
                raise RuntimeError(f".srs 校验失败: {key} 回读异常 {exc}") from exc
            for w in want:
                net = ipaddress.ip_network(str(w), strict=False)
                if not any(net.version == o.version and net.subnet_of(o) for o in nets):
                    raise RuntimeError(f".srs 校验失败: {key} 丢失 {w}")
            merged += max(0, len(want) - len(have))
        else:
            want_s, have_s = set(map(str, want)), set(have)
            if want_s != have_s:
                missing = sorted(want_s - have_s)
                extra = sorted(have_s - want_s)
                raise RuntimeError(
                    f".srs 校验失败: {key} 丢失 {len(missing)} 条 {missing[:3]}"
                    f"{f'，多出 {len(extra)} 条 {extra[:3]}' if extra else ''}"
                )
    return merged


def write_outputs(
    builder: SetBuilder,
    name: str,
    out_dir: Path,
    split_ip: bool,
    separate_url_regex: bool,
    ip_source: bool,
    singbox: str | None,
    result: Result,
    ip_suffix: str = "_ip",
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    domain_items = [i for i in ITEM_ORDER if i not in IP_ITEMS]
    ip_items = [i for i in ITEM_ORDER if i in IP_ITEMS]

    has_domain = builder.has(domain_items)
    has_ip = builder.has(ip_items)
    # URL-REGEX 降级出来的正则单独成集：可以在 route.rules 里排在主集合之前，
    # 让"精确的那几条"走另一套策略，剩下的照旧（sing-box 的 rule-set 内部是 OR，
    # 想分流只能拆文件，靠规则顺序生效）。
    url_rx = frozenset(builder.url_regex_items) if separate_url_regex else frozenset()

    # 默认一个源就一个集合：域名 + IP + 进程 + 端口全在一起，config 里引用一个 tag 就够。
    # --split-ip 时才按用途拆开（DNS 阶段只能用域名类 rule-set，IP 只能在路由阶段生效）：
    #   <name>.json            域名类（domain/suffix/keyword/regex + process/port）
    #   <name>_ip_cidr.json    IP 类（ip_cidr / source_ip_cidr）      --names modern 时为 _ip
    #   <name>_url_regex.json  URL-REGEX 降级来的正则（仅 --separate-url-regex）
    # 唯一例外：源本身是 IP 列表（URL 路径里有 `/ip/` 段，或名字以 `_ip`/`_cidr` 结尾），
    # 那 IP 规则留在原名下、域名部分加 _domain，避免出现 xxx_ip_ip.json。
    # legacy 命名（IP 后缀是 _ip_cidr）不翻转，保持"主=域名、IP 加 _ip_cidr"的老布局。
    ip_named = ip_suffix == "_ip" and (
        ip_source or re.search(r"_(ip|ipv6|cidr)$", name, re.I) is not None)
    sets: list[tuple[str, dict]] = []
    if split_ip and has_domain and has_ip:
        if ip_named:
            sets.append((name, builder.build(ip_items)))
            sets.append((f"{name}_domain", builder.build(domain_items, drop=url_rx)))
        else:
            sets.append((name, builder.build(domain_items, drop=url_rx)))
            sets.append((f"{name}{ip_suffix}", builder.build(ip_items)))
    else:
        sets.append((name, builder.build(domain_items + ip_items, drop=url_rx)))
    if url_rx:                       # 单独文件里只放这批降级来的正则
        sets.append((f"{name}_url_regex", builder.build(["domain_regex"], only=url_rx)))

    wrote_any = False
    for set_name, doc in sets:
        if not doc["rules"]:
            continue
        wrote_any = True
        json_path = out_dir / f"{set_name}.json"
        # version 在前、item 按 ITEM_ORDER 排列（与 skk 官方产物观感一致），
        # 确定性由排序好的列表保证，不依赖 sort_keys
        json_path.write_text(
            json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        counts: dict[str, int] = {}
        for rule_obj in doc["rules"]:
            for k, v in rule_obj.items():
                counts[k] = counts.get(k, 0) + len(v)
        result.parts[set_name] = counts
        if set_name == name:
            result.counts = counts
        result.files.append(str(json_path))
        result.json_bytes += json_path.stat().st_size

        if singbox:
            srs_path = json_path.with_suffix(".srs")
            compile_rule_set(singbox, json_path, srs_path)
            # 编译器可能合并相邻 CIDR，合并条数单独记
            result.merged_ip += verify_rule_set(
                singbox, srs_path,
                {k: v for rule_obj in doc["rules"] for k, v in rule_obj.items()})
            result.files.append(str(srs_path))
            result.srs_bytes += srs_path.stat().st_size

    if not wrote_any:
        # 源里没有一个可转换的规则（如纯 IP-ASN 列表）：仍写出一个空集合，
        # 这样 sing-box config 里已有的引用不会因为文件消失而启动失败。
        empty = {"version": builder.rule_version, "rules": []}
        json_path = out_dir / f"{name}.json"
        json_path.write_text(json.dumps(empty, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8")
        result.files.append(str(json_path))
        result.json_bytes += json_path.stat().st_size
        if singbox:
            srs_path = json_path.with_suffix(".srs")
            compile_rule_set(singbox, json_path, srs_path)
            result.files.append(str(srs_path))
            result.srs_bytes += srs_path.stat().st_size

    if builder.dropped:
        dump = out_dir / f"{name}.dropped.txt"
        with dump.open("w", encoding="utf-8") as fh:
            for reason, raw in builder.dropped:
                fh.write(f"{reason}\t{raw}\n")
        result.dropped = {}
        for reason, _ in builder.dropped:
            result.dropped[reason] = result.dropped.get(reason, 0) + 1
        result.lossy = sum(n for r, n in result.dropped.items() if r.startswith("lossy:"))


def process_one(
    url: str,
    name: str,
    out_dir: Path,
    args: argparse.Namespace,
) -> Result:
    started = time.time()
    result = Result(url=url, name=name, ok=False)
    try:
        text = fetch_text(url, args.timeout, args.retries)
        builder = SetBuilder(
            rule_version=args.rule_version,
            wildcard_single_label=args.wildcard_single_label,
            url_regex_mode=args.url_regex,
            extra_excluded={d for d in (normalize_domain(x) for x in args.exclude_domain) if d},
        )
        parse_document(text, builder)
        result.parsed = builder.parsed
        # 源是不是"IP 列表"：看 URL 路径里有没有独立的 /ip/ 段
        path = "/" + urlsplit(url).path.strip("/") + "/"
        ip_source = bool(re.search(r"/(ip|ipv6|cidr)/", path, re.I))
        write_outputs(
            builder, name, out_dir, args.split_ip, args.separate_url_regex,
            ip_source, None if args.no_compile else args.singbox, result,
            ip_suffix="_ip_cidr" if args.names == "legacy" else "_ip",
        )
        result.kept = sum(n for counts in result.parts.values() for n in counts.values())
        if result.kept == 0:
            # 不是失败：像 telegram_asn 这种纯 IP-ASN 源，sing-box 本来就没有对应 item
            result.skipped = True
            reasons = ", ".join(f"{k}×{v}" for k, v in sorted(result.dropped.items())) or "空文件"
            result.warning = f"没有可转换的规则（{reasons}），已写出空集合"
        if result.dropped:
            result.warning = "部分规则未转换或已降级（见 .dropped.txt）"
        result.ok = True
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    result.seconds = time.time() - started
    return result


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def read_rules_list(path: Path) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            urls.append(line)
    return urls


def human(n: int) -> str:
    return f"{n:,}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Surge/Clash 规则 -> sing-box rule-set")
    ap.add_argument("--rules-list", default=None,
                    help="链接列表文件（默认 <脚本目录>/RulesList.txt）")
    ap.add_argument("--out", default=None,
                    help="输出目录（默认 <脚本目录>/Rules）")
    ap.add_argument("--singbox", default="sing-box", help="sing-box 可执行文件路径")
    ap.add_argument("--jobs", type=int, default=8, help="并发链接数")
    ap.add_argument("--timeout", type=float, default=60.0, help="单次抓取超时(秒)")
    ap.add_argument("--retries", type=int, default=2, help="抓取重试次数")
    ap.add_argument("--rule-version", type=int, default=2, choices=(1, 2, 3),
                    help="输出 rule-set 的 version 字段(默认 2，兼容 1.8+)")
    ap.add_argument("--split-ip", action="store_true",
                    help="把 IP 类规则拆成单独的 _ip/_ip_cidr 集合（默认不拆，全放一个集合）")
    ap.add_argument("--exclude-domain", action="append", default=[], metavar="DOMAIN",
                    help="额外排除的域名（可重复；默认已排除 skk 的演练域名）")
    ap.add_argument("--no-compile", action="store_true", help="只写 json，不编译 .srs")
    ap.add_argument("--wildcard-single-label", action="store_true",
                    help="DOMAIN-WILDCARD 的 * 只匹配一个 label（默认按 Surge 官方语义跨点匹配）")
    ap.add_argument("--wildcard-greedy", action="store_true",
                    help="已废弃：现在默认就是跨点匹配，保留只为兼容旧命令")
    ap.add_argument("--url-regex", choices=("host", "drop"), default="host",
                    help="URL-REGEX 处理方式：host=降级为域名正则并保留(默认)，drop=丢弃并记录")
    ap.add_argument("--separate-url-regex", action="store_true",
                    help="把 URL-REGEX 降级来的正则拆成独立的 _url_regex 集合（默认并入主集合）")
    ap.add_argument("--strict", action="store_true", help="有任何规则被丢弃就以非 0 退出")
    ap.add_argument("--quiet", action="store_true", help="只打印汇总")
    ap.add_argument("--report", default=None, help="把详细报告写到该 json 文件(默认 <out>/report.json)")
    ap.add_argument("--names", choices=("legacy", "modern"), default="legacy",
                    help="产物命名：legacy=basename 前段 + _ip_cidr（与原脚本一致，默认）；"
                         "modern=skk_/owner_ 前缀 + _ip")
    args = ap.parse_args(argv)

    # 默认相对脚本自身：脚本旁边的 RulesList.txt -> 脚本旁边的 Rules/ 目录
    rules_path = Path(args.rules_list) if args.rules_list else DEFAULT_RULES_LIST
    if not rules_path.exists():
        print(f"找不到链接列表：{rules_path}", file=sys.stderr)
        return 2
    urls = read_rules_list(rules_path)
    if not urls:
        print("链接列表是空的", file=sys.stderr)
        return 2

    singbox = None
    if not args.no_compile:
        exe = args.singbox
        try:
            proc = subprocess.run([exe, "version"], capture_output=True, text=True)
            if proc.returncode != 0:
                raise OSError(proc.stderr.strip()[:200])
            print(f"sing-box: {proc.stdout.splitlines()[0].strip()}")
        except OSError as exc:
            print(f"警告：找不到可用的 sing-box（{exe}）：{exc}\n"
                  f"      继续只生成 json；用 --no-compile 可关掉该检查。", file=sys.stderr)
            args.no_compile = True
        if not args.no_compile:
            singbox = exe

    out_dir = Path(args.out) if args.out else DEFAULT_OUT
    out_dir.mkdir(parents=True, exist_ok=True)

    plan = resolve_names(urls, args.names, args.split_ip, args.separate_url_regex)

    if not args.quiet:
        print(f"共 {len(plan)} 条链接，输出到 {out_dir}/，并发 {args.jobs}\n")
    results: list[Result] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as ex:
        futures = {
            ex.submit(process_one, url, name, out_dir, args): (url, name)
            for url, name in plan
        }
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            results.append(res)
            flag = "SKIP" if res.skipped else ("OK  " if res.ok else "FAIL")
            detail = (
                f"{human(res.parsed):>8} 条 -> 保留 {human(res.kept):>8}"
                f"  json {res.json_bytes/1024:>8.1f}K  srs {res.srs_bytes/1024:>8.1f}K"
                f"  {res.seconds:5.2f}s"
            )
            if not args.quiet or not res.ok:
                print(f"[{flag}] {res.name:38} {detail}")
            if res.skipped:
                print(f"       {res.warning}")
            elif not res.ok:
                print(f"       {res.error}")
            elif not args.quiet:
                hard = {k: v for k, v in res.dropped.items() if not k.startswith("lossy:")}
                soft = {k: v for k, v in res.dropped.items() if k.startswith("lossy:")}
                if hard:
                    print("       丢弃: " + ", ".join(f"{k}×{v}" for k, v in sorted(hard.items())))
                if soft:
                    print("       降级保留: " + ", ".join(f"{k}×{v}" for k, v in sorted(soft.items())))
                if res.merged_ip:
                    print(f"       编译器合并 CIDR: {res.merged_ip} 条（语义等价）")
                if len(res.parts) > 1:
                    detail = "，".join(
                        f"{n}({sum(c.values())})" for n, c in res.parts.items())
                    print(f"       拆分为: {detail}")

    order = {name: i for i, (_, name) in enumerate(plan)}
    results.sort(key=lambda r: order.get(r.name, 0))

    failed = [r for r in results if not r.ok]
    skipped = [r for r in results if r.skipped]
    total_kept = sum(r.kept for r in results)
    total_lossy = sum(r.lossy for r in results)
    total_dropped = sum(sum(r.dropped.values()) for r in results) - total_lossy
    print(f"\n汇总：成功 {len(results) - len(failed) - len(skipped)}/{len(results)}"
          f"{f'，跳过 {len(skipped)}（无可转换规则）' if skipped else ''}，"
          f"保留 {human(total_kept)} 条，丢弃 {human(total_dropped)} 条"
          f"{f'，降级保留 {human(total_lossy)} 条' if total_lossy else ''}"
          f"{'（明细见各 .dropped.txt）' if total_dropped or total_lossy else ''}")
    if failed:
        print("失败链接：")
        for r in failed:
            print(f"  - {r.url}\n    {r.error}")

    report_path = Path(args.report) if args.report else out_dir / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "rule_version": args.rule_version,
                "singbox": singbox,
                "total_kept": total_kept,
                "total_dropped": total_dropped,
                "total_lossy": total_lossy,
                "sets": [
                    {
                        "url": r.url, "name": r.name, "ok": r.ok, "error": r.error,
                        "skipped": r.skipped, "warning": r.warning,
                        "parsed": r.parsed, "kept": r.kept,
                        "counts": r.counts, "parts": r.parts,
                        "dropped": r.dropped, "files": r.files,
                        "json_bytes": r.json_bytes, "srs_bytes": r.srs_bytes,
                        "merged_ip": r.merged_ip, "lossy": r.lossy,
                        "seconds": round(r.seconds, 2),
                    }
                    for r in results
                ],
            },
            ensure_ascii=False, indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    print(f"报告：{report_path}")

    if failed:
        return 1
    if args.strict and total_dropped:
        print("--strict：存在被丢弃的规则", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
