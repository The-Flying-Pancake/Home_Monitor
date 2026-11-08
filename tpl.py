"""Message templates for every Telegram text: notifications, workflow messages, the built-in
command replies and your own commands.

  {name}                     a placeholder
  {name|filter|filter:arg}   with filters (below), applied left to right
  {= up / total * 100 | round:1}
                             arithmetic on placeholders: + - * / % and ( ), with min(), max(),
                             round(x, n), abs(), floor(), ceil(). A name with dashes or a colon
                             goes in square brackets: {= [metric:temp.cpu-0] * 1.8 + 32}
  {if down > 0} ... {elif problems} ... {else} ... {end}
                             parts shown only when a condition holds: compare with > < >= <= == !=,
                             combine with and, or, not; text goes in quotes: {if state == "down"}.
                             A bare name is true when it is not empty and not 0.
  {{ and }}                  a literal brace

Filters
  upper lower title trim                 letters and spaces
  default:TEXT                           TEXT when the value is empty
  before:TEXT after:TEXT                 TEXT added only when the value is not empty
  round:N fixed:N int abs                numbers (N decimals; fixed keeps trailing zeros)
  add:N sub:N mul:N div:N                arithmetic on the value's number
  plural:WORD[:PLURAL]                   "3 devices", "1 device"
  bar[:N]                                a 0 to 100 value as a bar of N blocks (default 10): ▰▰▰▱▱
  truncate:N pad:N lpad:N                length
  replace:OLD:NEW                        text
  first:N last:N sort rsort count join[:SEP] unique
                                         for lists (one item per line): the first or last N, sorted
                                         (numbers by value), how many, on one line
  Arguments with a colon or a bar go in quotes: default:"n/a | none".

Numbers: a value such as "34%", "12 ms" or "-80 dBm" counts as its number in arithmetic,
comparisons and number filters.

Lines: a line whose placeholders were all empty and that holds nothing else is dropped, and a
line holding only {if}, {else} or {end} leaves no empty line behind. Unknown names stay as
written, so a typo shows; mistakes in a tag show as {?message}.

Nothing here can reach anything but the values handed in: there is no attribute access, no
loops and no exponent, and the size of the work is bounded by the template's length.
"""

import math
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

MAX_OUT = 3800
_NUM = re.compile(r"^\s*([-+]?\d+(?:[.,]\d+)?)")
_TAG = re.compile(r"\{\{|\}\}|\{([^{}\n]*)\}")


class TemplateError(Exception):
    pass


def number(value: Any) -> Optional[float]:
    """The number at the start of a value ("34%" -> 34.0), or None."""
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    m = _NUM.match(str(value if value is not None else ""))
    return float(m.group(1).replace(",", ".")) if m else None


def fmt(n: float, digits: Optional[int] = None) -> str:
    if digits is not None:
        n = round(n, digits)
        return f"{n:.{max(0, digits)}f}" if digits > 0 else str(int(n))
    if abs(n) < 1e15 and n == int(n):
        return str(int(n))
    return f"{n:.2f}".rstrip("0").rstrip(".")


# --- Expressions ---

_TOKEN = re.compile(r"\s*(?:(\d+(?:\.\d+)?)|\"([^\"]*)\"|'([^']*)'|\[([^\]]+)\]|([A-Za-z_][\w.:]*)|(>=|<=|==|!=|[-+*/%()<>,]))")
FUNCS: Dict[str, Callable[..., float]] = {
    "min": lambda *a: min(a), "max": lambda *a: max(a), "abs": lambda x: abs(x),
    "round": lambda x, n=0: round(x, int(n)), "floor": lambda x: math.floor(x), "ceil": lambda x: math.ceil(x),
}


def _tokens(expr: str) -> List[Tuple[str, Any]]:
    out, pos = [], 0
    expr = expr.strip()
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise TemplateError(f"cannot read '{expr[pos:pos + 10]}'")
        pos = m.end()
        num, s1, s2, br, name, op = m.groups()
        if num is not None:
            out.append(("num", float(num)))
        elif s1 is not None or s2 is not None:
            out.append(("str", s1 if s1 is not None else s2))
        elif br is not None:
            out.append(("name", br.strip()))
        elif name is not None:
            out.append(("op", name) if name in ("and", "or", "not") else ("name", name))
        else:
            out.append(("op", op))
    if len(out) > 200:
        raise TemplateError("too long")
    return out


class _Expr:
    """Recursive descent: or > and > not > comparison > + - > * / % > unary > atom."""

    def __init__(self, expr: str, values: Dict[str, Any], known: Optional[set]):
        self.t = _tokens(expr)
        self.i = 0
        self.values = values
        self.known = known
        self.missing = False

    def peek(self) -> Tuple[str, Any]:
        return self.t[self.i] if self.i < len(self.t) else ("end", None)

    def take(self, op: Optional[str] = None) -> Tuple[str, Any]:
        tok = self.peek()
        if op is not None and tok != ("op", op):
            raise TemplateError(f"expected '{op}'")
        self.i += 1
        return tok

    def run(self) -> Any:
        if not self.t:
            raise TemplateError("empty")
        v = self.or_()
        if self.i != len(self.t):
            raise TemplateError(f"unexpected '{self.peek()[1]}'")
        return v

    def or_(self) -> Any:
        v = self.and_()
        while self.peek() == ("op", "or"):
            self.take()
            r = self.and_()
            v = truthy(v) or truthy(r)
        return v

    def and_(self) -> Any:
        v = self.not_()
        while self.peek() == ("op", "and"):
            self.take()
            r = self.not_()
            v = truthy(v) and truthy(r)
        return v

    def not_(self) -> Any:
        if self.peek() == ("op", "not"):
            self.take()
            return not truthy(self.not_())
        return self.cmp()

    def cmp(self) -> Any:
        v = self.add()
        tok = self.peek()
        if tok[0] == "op" and tok[1] in ("<", ">", "<=", ">=", "==", "!="):
            self.take()
            r = self.add()
            a, b = number(v), number(r)
            if a is None or b is None:
                a, b = str(v if v is not None else "").lower(), str(r if r is not None else "").lower()
            return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b, "==": a == b, "!=": a != b}[tok[1]]
        return v

    def _num(self, v: Any) -> float:
        n = number(v)
        if n is None:
            raise TemplateError(f"'{v}' is not a number")
        return n

    def add(self) -> Any:
        v = self.mul()
        while self.peek() in (("op", "+"), ("op", "-")):
            op = self.take()[1]
            r = self.mul()
            v = self._num(v) + self._num(r) if op == "+" else self._num(v) - self._num(r)
        return v

    def mul(self) -> Any:
        v = self.unary()
        while self.peek() in (("op", "*"), ("op", "/"), ("op", "%")):
            op = self.take()[1]
            a, b = self._num(v), self._num(self.unary())
            if op == "*":
                v = a * b
            elif b == 0:
                raise TemplateError("division by zero")
            else:
                v = a / b if op == "/" else a % b
            if abs(v) > 1e18:
                raise TemplateError("number too large")
        return v

    def unary(self) -> Any:
        if self.peek() == ("op", "-"):
            self.take()
            return -self._num(self.unary())
        if self.peek() == ("op", "+"):
            self.take()
            return self._num(self.unary())
        return self.atom()

    def atom(self) -> Any:
        kind, val = self.take()
        if kind in ("num", "str"):
            return val
        if kind == "op" and val == "(":
            v = self.or_()
            self.take(")")
            return v
        if kind == "name":
            if self.peek() == ("op", "(") and val in FUNCS:
                self.take("(")
                args = []
                if self.peek() != ("op", ")"):
                    args.append(self._num(self.or_()))
                    while self.peek() == ("op", ","):
                        self.take()
                        args.append(self._num(self.or_()))
                self.take(")")
                try:
                    return FUNCS[val](*args)
                except (TypeError, ValueError) as exc:
                    raise TemplateError(f"{val}(): {exc}")
            if val in self.values and self.values[val] is not None:
                return self.values[val]
            if self.known is not None and val in self.known:
                self.missing = True
                return ""
            raise TemplateError(f"unknown name {val}")
        raise TemplateError(f"unexpected '{val}'")


def truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    s = str(v if v is not None else "").strip()
    if re.fullmatch(r"[-+]?\d+(?:[.,]\d+)?", s):
        return number(s) != 0          # "0" is false; "0%" or "0 ms" is text, so true
    return bool(s)


def evaluate(expr: str, values: Dict[str, Any], known: Optional[set] = None) -> Any:
    return _Expr(expr, values, known).run()


# --- Filters ---

def _split_args(text: str) -> List[str]:
    """Splits 'name:a:"b:c"' on colons outside quotes."""
    out, cur, quote = [], "", ""
    for ch in text:
        if quote:
            if ch == quote:
                quote = ""
            else:
                cur += ch
        elif ch in "\"'":
            quote = ch
        elif ch == ":":
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return out


def _split_pipes(text: str) -> List[str]:
    out, cur, quote = [], "", ""
    for ch in text:
        if quote:
            cur += ch
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            cur += ch
        elif ch == "|":
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return out


def _lines(v: str) -> List[str]:
    return [x for x in v.split("\n") if x.strip()]


def _int_arg(args: List[str], i: int, default: int, lo: int = 0, hi: int = 500) -> int:
    try:
        return max(lo, min(hi, int(float(args[i])))) if len(args) > i and args[i].strip() else default
    except ValueError:
        raise TemplateError(f"'{args[i]}' is not a whole number")


def _sort_key(line: str):
    n = number(re.sub(r"^\W+", "", line)) if number(line) is None else number(line)
    return (0, n, line.lower()) if n is not None else (1, 0, line.lower())


def _numeric(v: str, name: str) -> float:
    n = number(v)
    if n is None:
        raise TemplateError(f"{name}: '{v}' is not a number")
    return n


def apply_filter(value: Any, spec: str) -> str:
    args = _split_args(spec.strip())
    name = args.pop(0).strip().lower()
    v = "" if value is None else (fmt(value) if isinstance(value, float) else str(value))
    if name == "upper":
        return v.upper()
    if name == "lower":
        return v.lower()
    if name == "title":
        return v.title()
    if name == "trim":
        return v.strip()
    if name == "default":
        return v if v.strip() else (args[0] if args else "")
    if name == "before":
        return (args[0] if args else "") + v if v.strip() else v
    if name == "after":
        return v + (args[0] if args else "") if v.strip() else v
    if name in ("round", "fixed", "int", "abs"):
        if not v.strip():
            return v
        n = _numeric(v, name)
        if name == "int":
            return str(int(n))
        if name == "abs":
            return fmt(abs(n))
        d = _int_arg(args, 0, 0, 0, 10)
        return fmt(n, d) if name == "fixed" else fmt(round(n, d))
    if name in ("add", "sub", "mul", "div"):
        if not v.strip():
            return v
        n, by = _numeric(v, name), _numeric(args[0] if args else "", name)
        if name == "div" and by == 0:
            raise TemplateError("div: division by zero")
        return fmt({"add": n + by, "sub": n - by, "mul": n * by, "div": n / by if by else 0}[name])
    if name == "plural":
        n = number(v)
        word = args[0] if args else ""
        many = args[1] if len(args) > 1 else word + "s"
        return f"{v} {word if n == 1 else many}" if v.strip() else v
    if name == "bar":
        if not v.strip():
            return v
        width = _int_arg(args, 0, 10, 1, 40)
        n = max(0.0, min(100.0, _numeric(v, name)))
        full = int(round(n / 100 * width))
        return "▰" * full + "▱" * (width - full)
    if name == "truncate":
        n = _int_arg(args, 0, 40, 1, 4000)
        return v if len(v) <= n else v[:max(0, n - 1)].rstrip() + "…"
    if name == "pad":
        return v.ljust(_int_arg(args, 0, 10, 0, 80))
    if name == "lpad":
        return v.rjust(_int_arg(args, 0, 10, 0, 80))
    if name == "replace":
        if not args:
            raise TemplateError("replace needs OLD:NEW")
        return v.replace(args[0], args[1] if len(args) > 1 else "") if args[0] else v
    if name == "first":
        return "\n".join(_lines(v)[:_int_arg(args, 0, 5)])
    if name == "last":
        n = _int_arg(args, 0, 5)
        return "\n".join(_lines(v)[-n:] if n else [])
    if name == "sort":
        return "\n".join(sorted(_lines(v), key=_sort_key))
    if name == "rsort":
        return "\n".join(sorted(_lines(v), key=_sort_key, reverse=True))
    if name == "unique":
        seen, out = set(), []
        for x in _lines(v):
            if x not in seen:
                seen.add(x)
                out.append(x)
        return "\n".join(out)
    if name == "count":
        return str(len(_lines(v)))
    if name == "join":
        return (args[0] if args else ", ").join(x.strip() for x in _lines(v))
    raise TemplateError(f"unknown filter {name}")


FILTERS = ["upper", "lower", "title", "trim", "default", "before", "after", "round", "fixed", "int", "abs", "add", "sub",
           "mul", "div", "plural", "bar", "truncate", "pad", "lpad", "replace", "first", "last", "sort", "rsort", "unique",
           "count", "join"]


# --- Rendering ---

def _tag(body: str, values: Dict[str, Any], known: Optional[set]) -> Tuple[str, bool, bool]:
    """One {tag}: (text, was a placeholder, its value was missing or empty)."""
    parts = _split_pipes(body)
    head = parts[0].strip()
    try:
        if head.startswith("="):
            e = _Expr(head[1:], values, known)
            v = e.run()
            missing = e.missing
            v = fmt(v) if isinstance(v, float) else ("yes" if v is True else "no" if v is False else v)
        else:
            if not re.fullmatch(r"[\w.:-]+", head):
                return "{" + body + "}", False, False
            if head not in values or values[head] is None:
                if known is not None and head in known:
                    v, missing = "", True
                else:
                    return "{" + body + "}", False, False      # unknown: left as written
            else:
                v, missing = values[head], False
        for f in parts[1:]:
            v = apply_filter(v, f)
        text = "" if v is None else (fmt(v) if isinstance(v, float) else str(v))
        return text, True, missing or not text.strip()
    except TemplateError as exc:
        return "{?" + str(exc)[:80] + "}", False, False


def _blocks(text: str, values: Dict[str, Any], known: Optional[set]) -> str:
    """Resolves {if} blocks, leaving the chosen text (still with its placeholders)."""
    out: List[str] = []
    # stack of [showing now, a branch was taken, parent showing]
    stack: List[List[bool]] = []
    showing = True
    pos = 0
    pieces = []
    for m in _TAG.finditer(text):
        pieces.append((m.start(), m.end(), m.group(0), m.group(1)))
    for start, end, whole, body in pieces:
        kw = (body or "").strip()
        word = kw.split(None, 1)[0] if kw else ""
        if whole in ("{{", "}}") or word not in ("if", "elif", "else", "end"):
            continue
        # A tag alone on its line takes the line with it.
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", end)
        line_end = len(text) if line_end < 0 else line_end
        alone = not text[line_start:start].strip() and not text[end:line_end].strip()
        cut_from, cut_to = (line_start, min(len(text), line_end + 1)) if alone else (start, end)
        if cut_from < pos:
            cut_from = pos
        if showing:
            out.append(text[pos:cut_from])
        pos = cut_to
        cond = kw[len(word):].strip()
        try:
            if word == "if":
                ok = showing and truthy(evaluate(cond, values, known))
                stack.append([ok, ok, showing])
            elif word == "elif":
                if not stack:
                    raise TemplateError("elif without if")
                top = stack[-1]
                ok = top[2] and not top[1] and truthy(evaluate(cond, values, known))
                top[0] = ok
                top[1] = top[1] or ok
            elif word == "else":
                if not stack:
                    raise TemplateError("else without if")
                top = stack[-1]
                top[0] = top[2] and not top[1]
                top[1] = True
            else:
                if not stack:
                    raise TemplateError("end without if")
                stack.pop()
        except TemplateError as exc:
            if showing:
                out.append("{?" + str(exc)[:80] + "}")
            if word == "if":
                stack.append([False, True, showing])
        showing = stack[-1][0] if stack else True
    if showing:
        out.append(text[pos:])
    if stack:
        out.append("{?an if without end}")
    return "".join(out)


def render(text: str, values: Dict[str, Any], known: Optional[Iterable[str]] = None, drop_empty: bool = True,
           max_len: int = MAX_OUT) -> str:
    """Fills a template. known: names that are placeholders even when values lacks them (they come
    out empty); None means only the names in values."""
    if len(text) > 8000:
        text = text[:8000]
    known_set = set(known) if known is not None else None
    text = _blocks(text, values, known_set)
    out = []
    for line in text.split("\n"):
        any_tag, all_empty, literal = False, True, line
        pieces, last = [], 0
        for m in _TAG.finditer(line):
            pieces.append(line[last:m.start()])
            if m.group(0) == "{{":
                pieces.append("{")
            elif m.group(0) == "}}":
                pieces.append("}")
            else:
                done, was_tag, empty = _tag(m.group(1), values, known_set)
                pieces.append(done)
                if was_tag:
                    any_tag = True
                    all_empty = all_empty and empty
                else:
                    all_empty = False
            last = m.end()
        pieces.append(line[last:])
        done = "".join(pieces)
        rest = _TAG.sub("", literal).strip()
        if drop_empty and any_tag and all_empty and not rest and not done.strip():
            continue
        done = done.rstrip()
        if literal.startswith("{") and not literal.startswith("{{"):
            done = done.lstrip(" ")
        out.append(done)
    return "\n".join(out).strip("\n")[:max_len]


def names(text: str) -> List[str]:
    """The placeholder names a template uses (for checks)."""
    out = []
    for m in _TAG.finditer(text):
        body = m.group(1)
        if not body:
            continue
        head = _split_pipes(body)[0].strip()
        if re.fullmatch(r"[\w.:-]+", head) and head not in ("else", "end"):
            out.append(head)
    return out


# What the editors show under "Tricks": (what it does, example to insert).
TRICKS = [
    ("Only when something is down", "{if down > 0}\nDown: {down_list}\n{end}"),
    ("One thing or another", "{if problems == 0}✅ All good{else}⚠️ {problems} problems{end}"),
    ("Text comparison", "{if state == \"down\"}🔴{else}🟢{end}"),
    ("Arithmetic", "{= up / total * 100 | round:0}% up"),
    ("Round a number", "{cpu|round:0}"),
    ("A bar for a percentage", "{memory|bar:10} {memory}"),
    ("Words that count", "{count|plural:device}"),
    ("Fallback when empty", "{ping|default:\"no answer\"}"),
    ("Text only when there is a value", "{ping|before:\"ping \"}"),
    ("First 5 lines of a list", "{list|first:5}"),
    ("Sort a list", "{list|sort}"),
    ("A list on one line", "{down_list|join:\", \"}"),
    ("Shorten long text", "{problem|truncate:40}"),
    ("Capitals", "{device|upper}"),
    ("A literal brace", "{{ and }}"),
]
