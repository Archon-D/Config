    ) -> dict:
        """items：要哪些 item 字段；only/drop：对取值再筛一层。"""
        rule: dict[str, list] = {}
        for key in ITEM_ORDER:
            if key not in items or not self.items[key]:
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
        return {"version": self.rule_version, "rules": [rule] if rule else []}
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
def resolve_names(urls: list[str], mode: str = "legacy") -> list[tuple[str, str]]:
    """
    给每条链接定产物名。
    legacy（默认，与原脚本一致）：basename 前段，如 reject.conf -> reject。
    但原脚本遇到同名是后写覆盖前写（59 个源里有 5 组，共丢 7,615 条规则），
    这里改成：最后一条保留原名（和旧产物名一致，config 不用改），
    前面的改成 <路径段>_<原名>（domainset/cdn.conf -> domainset_cdn），谁都不丢。
    """
    namer = legacy_name if mode == "legacy" else derive_name
    plan = [(url, namer(url)) for url in urls]
    taken = {name for _, name in plan}
    grouped: dict[str, list[int]] = {}
    for i, (_, name) in enumerate(plan):
        grouped.setdefault(name, []).append(i)
    for name, idxs in grouped.items():
        if len(idxs) < 2:
            continue
        winner = plan[idxs[-1]][0]
        for i in idxs[:-1]:
            url = plan[i][0]
            base = f"{path_token(url)}_{name}"
            new, n = base, 2
            while new in taken:
                new, n = f"{base}-{n}", n + 1
            taken.add(new)
            plan[i] = (url, new)
            print(f"同名处理：{url}\n"
                  f"          -> {new}.json（{name}.json 仍由 {winner} 提供）",
                  file=sys.stderr)
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
    # 域名类规则和 IP 规则必须分开：sing-box 的 DNS 阶段只能用域名类 rule-set，
    # IP 规则只能在路由阶段生效。命名固定，不看两边条数多少：
    #   <name>.json        域名类（domain/suffix/keyword/regex + process_name/port）
    #   <name>_ip.json     IP 类（ip_cidr / source_ip_cidr）
    #   <name>_url_regex.json  URL-REGEX 降级来的正则（仅 --separate-url-regex 时才有）
    # 源里只有 IP 规则时只出一个 <name>.json，不会产生名字带上双 _ip 的空文件。
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
    for set_name, doc in sets:
        if not doc["rules"]:
            continue
        json_path = out_dir / f"{set_name}.json"
        # version 在前、item 按 ITEM_ORDER 排列（与 skk 官方产物观感一致），
        # 确定性由排序好的列表保证，不依赖 sort_keys
        json_path.write_text(
            json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        counts = {k: len(v) for k, v in doc["rules"][0].items()}
        result.parts[set_name] = counts
        if set_name == name:
            result.counts = counts
        result.files.append(str(json_path))
        result.json_bytes += json_path.stat().st_size
        if singbox:
            srs_path = json_path.with_suffix(".srs")
            compile_rule_set(singbox, json_path, srs_path)
            # 编译器可能合并相邻 CIDR，合并条数单独记
            result.merged_ip += verify_rule_set(singbox, srs_path, doc["rules"][0])
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
            wildcard_greedy=args.wildcard_greedy,
            url_regex_mode=args.url_regex,
        )
        parse_document(text, builder)
        result.parsed = builder.parsed
        # 源是不是"IP 列表"：看 URL 路径里有没有独立的 /ip/ 段
        path = "/" + urlsplit(url).path.strip("/") + "/"
        ip_source = bool(re.search(r"/(ip|ipv6|cidr)/", path, re.I))
        write_outputs(
            builder, name, out_dir, not args.no_split_ip, args.separate_url_regex,
            ip_source, None if args.no_compile else args.singbox, result,
            ip_suffix="_ip_cidr" if args.names == "legacy" else "_ip",
        )
        result.kept = sum(n for counts in result.parts.values() for n in counts.values())
        if result.kept == 0:
            raise RuntimeError("没有解析出任何可用规则")
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
    ap.add_argument("--no-split-ip", action="store_true", help="域名与 IP 不拆成两个文件")
    ap.add_argument("--no-compile", action="store_true", help="只写 json，不编译 .srs")
    ap.add_argument("--wildcard-greedy", action="store_true",
                    help="DOMAIN-WILDCARD 的 * 匹配任意字符(默认只匹配一个 label)")
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
    plan = resolve_names(urls, args.names)
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
            flag = "OK  " if res.ok else "FAIL"
            detail = (
                f"{human(res.parsed):>8} 条 -> 保留 {human(res.kept):>8}"
                f"  json {res.json_bytes/1024:>8.1f}K  srs {res.srs_bytes/1024:>8.1f}K"
                f"  {res.seconds:5.2f}s"
            )
            if not args.quiet or not res.ok:
                print(f"[{flag}] {res.name:38} {detail}")
            if not res.ok:
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
    total_kept = sum(r.kept for r in results)
    total_lossy = sum(r.lossy for r in results)
    total_dropped = sum(sum(r.dropped.values()) for r in results) - total_lossy
    print(f"\n汇总：成功 {len(results) - len(failed)}/{len(results)}，"
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
