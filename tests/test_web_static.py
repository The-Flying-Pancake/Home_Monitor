"""Static checks of the browser code for mistakes that fail silently.

The second half is a small reader for the project's JavaScript (no outside parser, by the project's
dependency rule). It proves that every value placed in an HTML template or an HTML sink is made safe,
so a new unescaped value fails here instead of reaching a page. It covers the JavaScript this project
writes, not the whole language: anything it cannot read stops the test with the file and line.
"""

import glob
import os
import re
import unittest

from tests import _env

DIALOG = re.compile(r"await\s+(?:confirmDialog|promptDialog|openHostKeys)\(")


class CurrentTargetTests(unittest.TestCase):
    def test_current_target_read_before_awaiting_a_dialog(self):
        # The browser clears event.currentTarget once the click has been dispatched: read after an
        # awaited dialog it is null, and the handler stops without a message (Fix SNMP Apply, 2026-11-02).
        found = []
        for path in glob.glob(os.path.join(_env.ROOT, "web", "*.js")):
            lines = open(path, encoding="utf-8").read().splitlines()
            for i, line in enumerate(lines):
                if not DIALOG.search(line):
                    continue
                for j in range(i, min(i + 15, len(lines))):
                    if j > i and re.match(r"\s*\}\);?\s*$", lines[j]):
                        break
                    if re.search(r"\b(?:ev|event|e)\.currentTarget\b", lines[j]) and j > i:
                        found.append(f"{os.path.basename(path)}:{j + 1}")
        self.assertEqual(found, [])


class PermissionTests(unittest.TestCase):
    def test_every_permission_is_known_to_the_page(self):
        # A permission the page does not know is never hidden for those who lack it.
        import rbac
        with open(os.path.join(_env.ROOT, "web", "shell.js"), encoding="utf-8") as f:
            listed = re.search(r"const ALL_PERMISSIONS = \[(.*?)\];", f.read(), re.S).group(1)
        with open(os.path.join(_env.ROOT, "web", "style.css"), encoding="utf-8") as f:
            css = f.read()
        for key in rbac.PERMISSION_KEYS:
            self.assertIn(f'"{key}"', listed, key)
            cls = "lacks-" + key.replace(".", "-")
            self.assertIn(f'.{cls} [data-perm~="{key}"]', css, key)


# --- Reading JavaScript -------------------------------------------------------------------------

class JsError(Exception):
    pass


class Tok:
    __slots__ = ("type", "value", "start", "end", "newline", "parts", "exprs")

    def __init__(self, type_, value, start, end, newline):
        self.type, self.value, self.start, self.end, self.newline = type_, value, start, end, newline
        self.parts, self.exprs = None, None


# Names after which a slash starts a regular expression, not a division.
BEFORE_REGEX = {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else",
                "await", "yield"}
PUNCTUATORS = sorted([">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=", "=>", "==", "!=",
                      "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=",
                      "^=", "<<", ">>", "**", "{", "}", "(", ")", "[", "]", ";", ",", "<", ">", "+", "-", "*", "/",
                      "%", "&", "|", "^", "!", "~", "?", ":", "=", "."], key=len, reverse=True)


def _ident_start(c):
    return c.isalpha() or c in "_$"


def _ident_part(c):
    return c.isalnum() or c in "_$"


def tokenize(src, i=0, in_template=False):
    """Tokens from src[i:]. With in_template, stops at the } closing a ${ and returns (tokens, index after it)."""
    toks, n, depth, newline = [], len(src), 0, False
    while i < n:
        c = src[i]
        if c in " \t\r\n ﻿":
            newline = newline or c == "\n"
            i += 1
        elif src.startswith("//", i):
            while i < n and src[i] != "\n":
                i += 1
        elif src.startswith("/*", i):
            end = src.find("*/", i + 2)
            if end < 0:
                raise JsError(f"unclosed comment at {i}")
            newline = newline or "\n" in src[i:end]
            i = end + 2
        elif _ident_start(c):
            j = i + 1
            while j < n and _ident_part(src[j]):
                j += 1
            toks.append(Tok("name", src[i:j], i, j, newline))
            i, newline = j, False
        elif c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            m = re.compile(r"0[xXbBoO][0-9a-fA-F_]+n?|(\d[\d_]*)?(\.\d[\d_]*|\.)?([eE][+-]?\d+)?n?").match(src, i)
            toks.append(Tok("num", m.group(0), i, m.end(), newline))
            i, newline = m.end(), False
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == "\n":
                    raise JsError(f"line break in a string at {i}")
                j += 2 if src[j] == "\\" else 1
            if j >= n:
                raise JsError(f"unclosed string at {i}")
            toks.append(Tok("str", src[i + 1:j], i, j + 1, newline))
            i, newline = j + 1, False
        elif c == "`":
            tok, i = _template(src, i, newline)
            toks.append(tok)
            newline = False
        elif c == "/" and _regex_allowed(toks):
            j, in_class = i + 1, False
            while j < n and (in_class or src[j] != "/"):
                if src[j] == "\n":
                    raise JsError(f"line break in a regular expression at {i}")
                if src[j] == "\\":
                    j += 1
                elif src[j] == "[":
                    in_class = True
                elif src[j] == "]":
                    in_class = False
                j += 1
            j += 1
            while j < n and _ident_part(src[j]):
                j += 1
            toks.append(Tok("regex", src[i:j], i, j, newline))
            i, newline = j, False
        else:
            for p in PUNCTUATORS:
                if src.startswith(p, i):
                    break
            else:
                raise JsError(f"unexpected character {c!r} at {i}")
            if p == "?." and i + 2 < n and src[i + 2].isdigit():
                p = "?"
            if in_template:
                if p == "{":
                    depth += 1
                elif p == "}":
                    if depth == 0:
                        return toks, i + 1
                    depth -= 1
            toks.append(Tok("punct", p, i, i + len(p), newline))
            i, newline = i + len(p), False
    if in_template:
        raise JsError("unclosed ${ in a template")
    return toks, i


def _regex_allowed(toks):
    if not toks:
        return True
    last = toks[-1]
    if last.type in ("num", "str", "tpl", "regex"):
        return False
    if last.type == "name":
        return last.value in BEFORE_REGEX
    return last.value not in (")", "]", "}")


def _template(src, i, newline):
    start, n, parts, exprs, text = i, len(src), [], [], []
    i += 1
    while True:
        if i >= n:
            raise JsError(f"unclosed template at {start}")
        c = src[i]
        if c == "\\":
            text.append(src[i:i + 2])
            i += 2
        elif c == "`":
            parts.append("".join(text))
            tok = Tok("tpl", None, start, i + 1, newline)
            tok.parts, tok.exprs = parts, exprs
            return tok, i + 1
        elif src.startswith("${", i):
            parts.append("".join(text))
            text = []
            toks, i = tokenize(src, i + 2, in_template=True)
            exprs.append(toks)
        else:
            text.append(c)
            i += 1


class Node:
    def __init__(self, kind, start, end, **fields):
        self.kind, self.start, self.end, self.scope = kind, start, end, None
        self.__dict__.update(fields)

    def children(self):
        for key, value in self.__dict__.items():
            if key in ("scope", "fn_owner"):
                continue
            if isinstance(value, Node):
                yield value
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, Node):
                        yield item


BINARY = {"??": 1, "||": 2, "&&": 3, "|": 4, "^": 5, "&": 6, "==": 7, "!=": 7, "===": 7, "!==": 7, "<": 8, ">": 8,
          "<=": 8, ">=": 8, "instanceof": 8, "in": 8, "<<": 9, ">>": 9, ">>>": 9, "+": 10, "-": 10, "*": 11, "/": 11,
          "%": 11, "**": 12}
ASSIGN = {"=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "&&=", "||=", "??="}
UNARY = {"!", "-", "+", "~", "typeof", "void", "delete"}
NO_OPERAND = {")", "]", "}", ",", ";", ":"}


class Parser:
    def __init__(self, toks, end_pos=0):
        self.toks, self.i, self.end_pos = toks, 0, end_pos
        self.match = {}
        stack = []
        for idx, t in enumerate(toks):
            if t.type == "punct" and t.value in "([{":
                stack.append(idx)
            elif t.type == "punct" and t.value in ")]}" and stack:
                self.match[stack.pop()] = idx

    # Reading tokens

    def peek(self, offset=0):
        j = self.i + offset
        return self.toks[j] if j < len(self.toks) else None

    def at(self, value, offset=0):
        t = self.peek(offset)
        return t is not None and t.type in ("punct", "name") and t.value == value

    def eat(self, value):
        if self.at(value):
            self.i += 1
            return True
        return False

    def expect(self, value):
        if not self.eat(value):
            t = self.peek()
            where = t.start if t else self.end_pos
            raise JsError(f"expected {value!r} at {where}")

    def next(self):
        t = self.peek()
        if t is None:
            raise JsError(f"unexpected end at {self.end_pos}")
        self.i += 1
        return t

    def last_end(self):
        return self.toks[self.i - 1].end if self.i else 0

    def here(self):
        t = self.peek()
        return t.start if t else self.end_pos

    # Statements

    def program(self):
        body = []
        while self.peek() is not None:
            body.append(self.statement())
        return Node("Block", 0, self.end_pos, body=body, top=True)

    def block(self):
        start = self.here()
        self.expect("{")
        body = []
        while not self.at("}"):
            if self.peek() is None:
                raise JsError(f"unclosed block at {start}")
            body.append(self.statement())
        self.expect("}")
        return Node("Block", start, self.last_end(), body=body, top=False)

    def end_statement(self):
        self.eat(";")

    def statement(self):
        t = self.peek()
        start = t.start
        value = t.value if t.type in ("name", "punct") else None
        if value == "{":
            return self.block()
        if value == ";":
            self.i += 1
            return Node("Empty", start, start + 1)
        if value in ("const", "let", "var"):
            node = self.declaration()
            self.end_statement()
            return node
        if value == "function" or (value == "async" and self.at("function", 1)):
            fn = self.function()
            return Node("FnDecl", start, fn.end, fn=fn, name=fn.name)
        if value == "if":
            self.i += 1
            self.expect("(")
            test = self.expression()
            self.expect(")")
            then = self.statement()
            other = self.statement() if self.eat("else") else None
            return Node("If", start, self.last_end(), test=test, then=then, other=other)
        if value == "for":
            return self.for_statement()
        if value == "while":
            self.i += 1
            self.expect("(")
            test = self.expression()
            self.expect(")")
            return Node("While", start, self.last_end(), test=test, body=self.statement())
        if value == "do":
            self.i += 1
            body = self.statement()
            self.expect("while")
            self.expect("(")
            test = self.expression()
            self.expect(")")
            self.end_statement()
            return Node("While", start, self.last_end(), test=test, body=body)
        if value == "try":
            return self.try_statement()
        if value == "switch":
            return self.switch_statement()
        if value == "return":
            self.i += 1
            arg = None
            following = self.peek()
            if following is not None and not following.newline and not (self.at(";") or self.at("}")):
                arg = self.expression()
            self.end_statement()
            return Node("Return", start, self.last_end(), arg=arg)
        if value == "throw":
            self.i += 1
            arg = self.expression()
            self.end_statement()
            return Node("Throw", start, self.last_end(), arg=arg)
        if value in ("break", "continue"):
            self.i += 1
            following = self.peek()
            if following is not None and following.type == "name" and not following.newline:
                self.i += 1
            self.end_statement()
            return Node("Empty", start, self.last_end())
        if t.type == "name" and self.at(":", 1):
            self.i += 2
            return self.statement()
        expr = self.expression()
        self.end_statement()
        return Node("Expr", start, self.last_end(), expr=expr)

    def declaration(self, allow_in=True):
        start = self.here()
        decl_kind = self.next().value
        decls = []
        while True:
            pattern = self.pattern()
            init = None
            if self.eat("="):
                init = self.assignment()
            decls.append(Node("Declarator", pattern.start, self.last_end(), pattern=pattern, init=init))
            if not self.eat(","):
                break
        return Node("Var", start, self.last_end(), decl_kind=decl_kind, decls=decls)

    def pattern(self):
        """A name or a destructuring pattern. Default values are kept so that they are read too."""
        t = self.peek()
        start = t.start if t else self.end_pos
        if self.at("["):
            self.i += 1
            items = []
            while not self.at("]"):
                if self.eat(","):
                    continue
                items.append(self.pattern_item())
                if not self.at("]"):
                    self.expect(",")
            self.expect("]")
            return Node("Destructure", start, self.last_end(), items=items)
        if self.at("{"):
            self.i += 1
            items = []
            while not self.at("}"):
                if self.eat("..."):
                    items.append(self.pattern())
                else:
                    if self.at("["):
                        self.i += 1
                        self.assignment()
                        self.expect("]")
                        self.expect(":")
                        items.append(self.pattern_item())
                    else:
                        key = self.next()
                        if self.eat(":"):
                            items.append(self.pattern_item())
                        else:
                            item = Node("Name", key.start, key.end, name=key.value)
                            if self.eat("="):
                                self.assignment()
                            items.append(item)
                if not self.at("}"):
                    self.expect(",")
            self.expect("}")
            return Node("Destructure", start, self.last_end(), items=items)
        name = self.next()
        if name.type != "name":
            raise JsError(f"expected a name at {name.start}")
        return Node("Name", name.start, name.end, name=name.value)

    def pattern_item(self):
        if self.eat("..."):
            return self.pattern()
        item = self.pattern()
        if self.eat("="):
            self.assignment()
        return item

    def for_statement(self):
        start = self.here()
        self.expect("for")
        self.eat("await")
        self.expect("(")
        init = None
        if self.at("const") or self.at("let") or self.at("var"):
            save = self.i
            decl_kind = self.next().value
            pattern = self.pattern()
            if self.at("of") or self.at("in"):
                self.i += 1
                right = self.expression()
                self.expect(")")
                return Node("ForIn", start, self.last_end(), decl_kind=decl_kind, pattern=pattern, right=right,
                            target=None, body=self.statement())
            self.i = save
            init = self.declaration()
        elif self.peek().type == "name" and (self.at("of", 1) or self.at("in", 1)):
            name = self.next()
            self.i += 1
            right = self.expression()
            self.expect(")")
            target = Node("Ident", name.start, name.end, name=name.value)
            return Node("ForIn", start, self.last_end(), decl_kind=None, pattern=None, right=right, target=target,
                        body=self.statement())
        elif not self.at(";"):
            init = self.expression()
        self.expect(";")
        test = None if self.at(";") else self.expression()
        self.expect(";")
        update = None if self.at(")") else self.expression()
        self.expect(")")
        return Node("For", start, self.last_end(), init=init, test=test, update=update, body=self.statement())

    def try_statement(self):
        start = self.here()
        self.expect("try")
        block = self.block()
        param, handler, finalizer = None, None, None
        if self.eat("catch"):
            if self.eat("("):
                param = self.pattern()
                self.expect(")")
            handler = self.block()
        if self.eat("finally"):
            finalizer = self.block()
        return Node("Try", start, self.last_end(), block=block, param=param, handler=handler, finalizer=finalizer)

    def switch_statement(self):
        start = self.here()
        self.expect("switch")
        self.expect("(")
        disc = self.expression()
        self.expect(")")
        self.expect("{")
        body = []
        while not self.at("}"):
            if self.eat("case"):
                body.append(Node("Expr", self.here(), self.here(), expr=self.expression()))
                self.expect(":")
            elif self.eat("default"):
                self.expect(":")
            else:
                body.append(self.statement())
        self.expect("}")
        return Node("Switch", start, self.last_end(), disc=disc, body=body)

    # Functions

    def function(self):
        start = self.here()
        self.eat("async")
        self.expect("function")
        name = None
        if self.peek().type == "name" and not self.at("("):
            name = self.next().value
        params = self.params()
        body = self.block()
        return Node("Fn", start, body.end, name=name, params=params, body=body, arrow=False)

    def params(self):
        self.expect("(")
        items = []
        while not self.at(")"):
            items.append(self.param())
            if not self.at(")"):
                self.expect(",")
        self.expect(")")
        return items

    def param(self):
        self.eat("...")
        pattern = self.pattern()
        default = self.assignment() if self.eat("=") else None
        return Node("Param", pattern.start, self.last_end(), pattern=pattern, default=default)

    def arrow_body(self, start, params):
        self.expect("=>")
        if self.at("{"):
            body = self.block()
        else:
            body = self.assignment()
        return Node("Fn", start, body.end, name=None, params=params, body=body, arrow=True)

    def is_arrow_here(self):
        if self.at("("):
            close = self.match.get(self.i)
            if close is None or close + 1 >= len(self.toks):
                return False
            after = self.toks[close + 1]
            return after.type == "punct" and after.value == "=>"
        t = self.peek()
        return t is not None and t.type == "name" and self.at("=>", 1)

    def arrow(self):
        start = self.here()
        if self.at("("):
            params = self.params()
        else:
            name = self.next()
            pattern = Node("Name", name.start, name.end, name=name.value)
            params = [Node("Param", name.start, name.end, pattern=pattern, default=None)]
        return self.arrow_body(start, params)

    # Expressions

    def expression(self):
        start = self.here()
        first = self.assignment()
        if not self.at(","):
            return first
        items = [first]
        while self.eat(","):
            items.append(self.assignment())
        return Node("Seq", start, self.last_end(), items=items)

    def assignment(self):
        t = self.peek()
        if t is None:
            raise JsError(f"unexpected end at {self.end_pos}")
        start = t.start
        if self.at("async") and self.peek(1) is not None and not self.peek(1).newline:
            self.i += 1
            if self.at("function"):
                self.i -= 1
            elif self.is_arrow_here():
                node = self.arrow()
                node.start = start
                return node
            else:
                self.i -= 1
        if self.is_arrow_here():
            return self.arrow()
        left = self.conditional()
        o = self.peek()
        if o is not None and o.type == "punct" and o.value in ASSIGN:
            self.i += 1
            value = self.assignment()
            return Node("Assign", start, self.last_end(), op=o.value, target=left, value=value)
        return left

    def conditional(self):
        start = self.here()
        test = self.binary(1)
        if self.eat("?"):
            a = self.assignment()
            self.expect(":")
            b = self.assignment()
            return Node("Cond", start, self.last_end(), test=test, a=a, b=b)
        return test

    def binary(self, level):
        start = self.here()
        left = self.unary()
        while True:
            o = self.peek()
            if o is None or o.type not in ("punct", "name") or o.value not in BINARY or BINARY[o.value] < level:
                return left
            self.i += 1
            right = self.binary(BINARY[o.value] + 1)
            left = Node("Binary", start, self.last_end(), op=o.value, left=left, right=right)

    def unary(self):
        t = self.peek()
        if t is None:
            raise JsError(f"unexpected end at {self.end_pos}")
        if t.type in ("punct", "name") and t.value in UNARY:
            self.i += 1
            arg = self.unary()
            return Node("Unary", t.start, self.last_end(), op=t.value, arg=arg)
        if t.type == "punct" and t.value in ("++", "--"):
            self.i += 1
            arg = self.unary()
            return Node("Update", t.start, self.last_end(), arg=arg)
        if t.type == "name" and t.value == "await":
            self.i += 1
            arg = self.unary()
            return Node("Await", t.start, self.last_end(), arg=arg)
        node = self.postfix()
        following = self.peek()
        if following is not None and following.type == "punct" and following.value in ("++", "--") and not following.newline:
            self.i += 1
            node = Node("Update", node.start, self.last_end(), arg=node)
        return node

    def args(self):
        self.expect("(")
        items = []
        while not self.at(")"):
            if self.at("..."):
                start = self.here()
                self.i += 1
                arg = self.assignment()
                items.append(Node("Spread", start, self.last_end(), arg=arg))
            else:
                items.append(self.assignment())
            if not self.at(")"):
                self.expect(",")
        self.expect(")")
        return items

    def postfix(self):
        start = self.here()
        if self.at("new"):
            node = self.new_expression()
        else:
            node = self.primary()
        while True:
            if self.eat("."):
                name = self.next()
                node = Node("Member", start, name.end, obj=node, prop=name.value, computed=None)
            elif self.at("?."):
                self.i += 1
                if self.at("("):
                    node = Node("Call", start, 0, callee=node, args=self.args())
                    node.end = self.last_end()
                elif self.eat("["):
                    computed = self.expression()
                    self.expect("]")
                    node = Node("Member", start, self.last_end(), obj=node, prop=None, computed=computed)
                else:
                    name = self.next()
                    node = Node("Member", start, name.end, obj=node, prop=name.value, computed=None)
            elif self.eat("["):
                computed = self.expression()
                self.expect("]")
                node = Node("Member", start, self.last_end(), obj=node, prop=None, computed=computed)
            elif self.at("("):
                node = Node("Call", start, 0, callee=node, args=self.args())
                node.end = self.last_end()
            else:
                return node

    def new_expression(self):
        start = self.here()
        self.expect("new")
        if self.at("new"):
            callee = self.new_expression()
        else:
            callee = self.primary()
        while self.eat("."):
            name = self.next()
            callee = Node("Member", start, name.end, obj=callee, prop=name.value, computed=None)
        args = self.args() if self.at("(") else []
        return Node("New", start, self.last_end(), callee=callee, args=args)

    def primary(self):
        t = self.next()
        if t.type == "num":
            return Node("Num", t.start, t.end)
        if t.type == "str":
            return Node("Str", t.start, t.end)
        if t.type == "regex":
            return Node("Regex", t.start, t.end)
        if t.type == "tpl":
            exprs = []
            for toks in t.exprs:
                sub = Parser(toks, t.end)
                exprs.append(sub.expression())
                if sub.peek() is not None:
                    raise JsError(f"could not read the end of a ${{}} at {sub.here()}")
            return Node("Tpl", t.start, t.end, parts=t.parts, exprs=exprs)
        if t.type == "punct":
            if t.value == "(":
                node = self.expression()
                self.expect(")")
                return node
            if t.value == "[":
                return self.array(t.start)
            if t.value == "{":
                return self.object(t.start)
            raise JsError(f"unexpected {t.value!r} at {t.start}")
        if t.value == "function" or (t.value == "async" and self.at("function")):
            self.i -= 1
            return self.function()
        if t.value in ("true", "false", "null"):
            return Node("Num", t.start, t.end)
        if t.value == "this":
            return Node("This", t.start, t.end)
        return Node("Ident", t.start, t.end, name=t.value)

    def array(self, start):
        items = []
        while not self.at("]"):
            if self.eat(","):
                continue
            if self.at("..."):
                s = self.here()
                self.i += 1
                arg = self.assignment()
                items.append(Node("Spread", s, self.last_end(), arg=arg))
            else:
                items.append(self.assignment())
            if not self.at("]"):
                self.expect(",")
        self.expect("]")
        return Node("Arr", start, self.last_end(), items=items)

    def object(self, start):
        values = []
        while not self.at("}"):
            if self.at("..."):
                s = self.here()
                self.i += 1
                arg = self.assignment()
                values.append(Node("Spread", s, self.last_end(), arg=arg))
            else:
                s = self.here()
                prefix_async = self.at("async") and not (self.at(",", 1) or self.at(":", 1) or self.at("(", 1) or self.at("}", 1))
                if prefix_async:
                    self.i += 1
                if (self.at("get") or self.at("set")) and not (self.at(",", 1) or self.at(":", 1) or self.at("(", 1) or self.at("}", 1)):
                    self.i += 1
                key = self.peek()
                if self.eat("["):
                    values.append(self.assignment())
                    self.expect("]")
                else:
                    key = self.next()
                if self.at("("):
                    params = self.params()
                    body = self.block()
                    values.append(Node("Fn", s, body.end, name=None, params=params, body=body, arrow=False))
                elif self.eat(":"):
                    values.append(self.assignment())
                else:
                    values.append(Node("Ident", key.start, key.end, name=key.value))
            if not self.at("}"):
                self.expect(",")
        self.expect("}")
        return Node("Obj", start, self.last_end(), values=values)


# --- Who declares what --------------------------------------------------------------------------

class Binding:
    def __init__(self, kind, init=None):
        self.kind, self.init, self.assigns, self.unsafe_assign = kind, init, [], False


class Scope:
    def __init__(self, parent, is_function=False):
        self.parent, self.is_function, self.names = parent, is_function, {}

    def function_scope(self):
        s = self
        while not s.is_function:
            s = s.parent
        return s

    def lookup(self, name):
        s = self
        while s is not None:
            if name in s.names:
                return s.names[name]
            s = s.parent
        return None


def _pattern_names(pattern):
    if pattern.kind == "Name":
        yield pattern.name
    else:
        for item in pattern.items:
            yield from _pattern_names(item)


def bind(node, scope, assigns):
    """Declares every name in its scope, sets node.scope and collects assignments to apply afterwards."""
    node.scope = scope
    kind = node.kind
    if kind == "Fn":
        inner = Scope(scope, is_function=True)
        node.scope = inner
        if node.name and not node.arrow:
            inner.names.setdefault(node.name, Binding("fn", node))
        for param in node.params:
            names = list(_pattern_names(param.pattern))
            binding_kind = getattr(param, "binding_kind", "param")
            for name in names:
                inner.names[name] = Binding(binding_kind if param.pattern.kind == "Name" else "param")
            if param.default is not None:
                bind(param.default, inner, assigns)
        bind_body = node.body.body if node.body.kind == "Block" else None
        if bind_body is not None:
            node.body.scope = inner
            for stmt in bind_body:
                bind(stmt, inner, assigns)
        else:
            bind(node.body, inner, assigns)
        return
    if kind == "Block":
        inner = scope if node.top else Scope(scope)
        node.scope = inner
        for stmt in node.body:
            bind(stmt, inner, assigns)
        return
    if kind == "FnDecl":
        scope.names[node.name] = Binding("fn", node.fn)
        bind(node.fn, scope, assigns)
        return
    if kind == "Var":
        target = scope.function_scope() if node.decl_kind == "var" else scope
        for decl in node.decls:
            pattern = decl.pattern
            if pattern.kind == "Name":
                target.names[pattern.name] = Binding("var", decl.init)
            else:
                for name in _pattern_names(pattern):
                    target.names[name] = Binding("param")
            if decl.init is not None:
                bind(decl.init, scope, assigns)
        return
    if kind == "For":
        inner = Scope(scope)
        node.scope = inner
        for part in (node.init, node.test, node.update, node.body):
            if part is not None:
                bind(part, inner, assigns)
        return
    if kind == "ForIn":
        inner = Scope(scope)
        node.scope = inner
        if node.pattern is not None:
            for name in _pattern_names(node.pattern):
                inner.names[name] = Binding("param")
        else:
            assigns.append((node.target.name, inner, None, "unsafe"))
        bind(node.right, inner, assigns)
        bind(node.body, inner, assigns)
        return
    if kind == "Try":
        bind(node.block, scope, assigns)
        if node.handler is not None:
            inner = Scope(scope)
            if node.param is not None:
                for name in _pattern_names(node.param):
                    inner.names[name] = Binding("param")
            bind(node.handler, inner, assigns)
        if node.finalizer is not None:
            bind(node.finalizer, scope, assigns)
        return
    if kind == "Switch":
        inner = Scope(scope)
        node.scope = inner
        bind(node.disc, inner, assigns)
        for stmt in node.body:
            bind(stmt, inner, assigns)
        return
    if kind == "Assign":
        target = node.target
        if target.kind == "Ident":
            assigns.append((target.name, scope, node.value, node.op))
        elif target.kind in ("Arr", "Obj"):
            for child in _assigned_names(target):
                assigns.append((child, scope, None, "unsafe"))
    if kind == "Call":
        callee = node.callee
        mapper = None
        if callee.kind == "Member" and callee.prop in ("map", "forEach") and node.args and node.args[0].kind == "Fn":
            mapper = node.args[0]
        elif (callee.kind == "Member" and callee.prop == "from" and callee.obj.kind == "Ident" and callee.obj.name == "Array"
              and len(node.args) > 1 and node.args[1].kind == "Fn"):
            mapper = node.args[1]
        if mapper is not None and len(mapper.params) > 1 and mapper.params[1].pattern.kind == "Name":
            mapper.params[1].binding_kind = "index"  # the callback's second argument is the position
    for child in node.children():
        bind(child, scope, assigns)


def _assigned_names(target):
    if target.kind == "Ident":
        yield target.name
    elif target.kind in ("Arr", "Obj"):
        for child in target.children():
            yield from _assigned_names(child)


# --- What counts as safe in HTML ----------------------------------------------------------------

SAFE_CALLS = {"escapeHtml", "Number", "parseInt", "parseFloat", "encodeURIComponent"}
NUMBER_ONLY_OPS = {"-", "*", "/", "%", "**", "|", "&", "^", "<<", ">>", ">>>"}
BOOLEAN_OPS = {"==", "!=", "===", "!==", "<", ">", "<=", ">=", "in", "instanceof"}
SAFE_METHODS = {"toFixed", "indexOf", "includes"}
SAFE_NAMES = {"undefined", "NaN", "Infinity"}
HTML_TEXT = re.compile(r"<[A-Za-z!/]|&[a-z#]")


class Analysis:
    def __init__(self, sources, allow=None):
        self.allow = {(f, _norm(t)): n for (f, t), (n, _why) in (allow or {}).items()}
        self.allowed_texts = {}
        for (f, t) in self.allow:
            self.allowed_texts.setdefault(f, set()).add(t)
        self.html, self.sinks, self.attrs, self.counts = [], [], [], {}
        self.sources, self.trees = sources, {}
        self.file_of = {}
        self.fn_results = {}
        self.var_results = {}
        self.seen_templates = set()
        shared = Scope(None, is_function=True)
        pending = []
        for name in sorted(sources):
            src = sources[name]
            try:
                toks, _ = tokenize(src)
                tree = Parser(toks, len(src)).program()
            except JsError as e:
                m = re.search(r"at (\d+)", str(e))
                line = src.count("\n", 0, int(m.group(1))) + 1 if m else 0
                raise JsError(f"{name}:{line}: {e}") from e
            self.trees[name] = tree
            # Every script shares one global scope: top-level names of all files are visible everywhere.
            bind(tree, shared, pending)
            self._index(tree, name)
        for name, scope, value, op in pending:
            binding = scope.lookup(name)
            if binding is None:
                continue
            if op == "unsafe" or op in ("&=", "|=") and value is None:
                binding.unsafe_assign = True
            elif op not in ("-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^="):
                binding.assigns.append(value)
        self._check_all()

    def _index(self, node, name):
        self.file_of[id(node)] = name
        for child in node.children():
            self._index(child, name)

    def text(self, node):
        return _norm(self.sources[self.file_of[id(node)]][node.start:node.end])

    def where(self, node):
        name = self.file_of[id(node)]
        line = self.sources[name].count("\n", 0, node.start) + 1
        return f"{name}:{line}: {self.text(node)}"

    def is_allowed(self, node):
        return self.text(node) in self.allowed_texts.get(self.file_of[id(node)], ())

    # The proof: blame(node) is None when the value is safe, or the node to report.

    def blame(self, node, narrowed=frozenset()):
        if self.is_allowed(node) or self.text(node) in narrowed:
            return None
        kind = node.kind
        if kind in ("Num", "Str", "Regex"):
            return None
        if kind == "Tpl":
            for expr in node.exprs:
                b = self.blame(expr, narrowed)
                if b is not None:
                    return b
            return None
        if kind == "Cond":
            inner = narrowed
            if node.test.kind == "Call" and node.test.callee.kind == "Ident" and node.test.callee.name == "isNum" and node.test.args:
                inner = narrowed | {self.text(node.test.args[0])}
            return self.blame(node.a, inner) or self.blame(node.b, narrowed)
        if kind == "Binary":
            if node.op in NUMBER_ONLY_OPS or node.op in BOOLEAN_OPS:
                return None
            if node.op == "&&":
                return self.blame(node.right, narrowed)
            return self.blame(node.left, narrowed) or self.blame(node.right, narrowed)
        if kind == "Unary":
            return None
        if kind == "Update":
            return None
        if kind == "Await":
            return self.blame(node.arg, narrowed)
        if kind == "Seq":
            return self.blame(node.items[-1], narrowed)
        if kind == "Ident":
            return self.blame_ident(node)
        if kind == "Member":
            return None if node.prop == "length" else node
        if kind == "New":
            return node
        if kind == "Call":
            return self.blame_call(node, narrowed)
        return node

    def blame_ident(self, node):
        if node.name in SAFE_NAMES:
            return None
        binding = node.scope.lookup(node.name) if node.scope is not None else None
        if binding is None or binding.kind == "fn":
            return node
        if binding.kind == "index":
            return None
        if binding.kind == "param" or binding.unsafe_assign:
            return node
        key = id(binding)
        if key in self.var_results:
            return node if self.var_results[key] is not True else None
        self.var_results[key] = False  # a cycle counts as unsafe
        values = ([binding.init] if binding.init is not None else []) + binding.assigns
        safe = all(self.blame(v) is None for v in values)
        self.var_results[key] = safe
        return None if safe else node

    def blame_call(self, node, narrowed):
        callee = node.callee
        if callee.kind == "Ident":
            if callee.name in SAFE_CALLS:
                return None
            fn = self.function_of(callee)
            if fn is not None:
                return self.blame_function(fn, node)
            return node
        if callee.kind != "Member":
            return node
        obj, prop = callee.obj, callee.prop
        if obj.kind == "Ident" and obj.name == "Math":
            return None
        if prop in SAFE_METHODS:
            return None
        if prop in ("toLocaleString", "toLocaleDateString", "toLocaleTimeString"):
            if self.is_number_or_date(obj):
                return None
            return node
        if prop == "join":
            return self.blame_join(node, narrowed)
        if prop == "replace" and len(node.args) == 2:
            # Only pieces already proved safe can end up in the result.
            return self.blame(obj, narrowed) or self.blame(node.args[1], narrowed)
        return node

    def is_number_or_date(self, node):
        if node.kind == "New":
            return node.callee.kind == "Ident" and node.callee.name == "Date"
        if node.kind == "Call" and node.callee.kind == "Ident":
            return node.callee.name in ("Number", "parseInt", "parseFloat")
        if node.kind == "Call" and node.callee.kind == "Member":
            return node.callee.obj.kind == "Ident" and node.callee.obj.name == "Math"
        return False

    def blame_join(self, node, narrowed):
        for arg in node.args:
            b = self.blame(arg, narrowed)
            if b is not None:
                return b
        source = node.callee.obj
        # .filter, .slice and .sort around the map change which items there are, never what they hold
        while source.kind == "Call" and source.callee.kind == "Member" and source.callee.prop in ("filter", "slice", "sort", "reverse"):
            source = source.callee.obj
        if source.kind == "Arr":
            for item in source.items:
                b = self.blame(item, narrowed)
                if b is not None:
                    return b
            return None
        if source.kind == "Call" and source.callee.kind == "Member" and source.callee.prop == "map" and source.args:
            return self.blame_mapper(source.args[0], node)
        if (source.kind == "Call" and source.callee.kind == "Member" and source.callee.prop == "from"
                and source.callee.obj.kind == "Ident" and source.callee.obj.name == "Array" and len(source.args) > 1):
            return self.blame_mapper(source.args[1], node)
        return node

    def blame_mapper(self, mapper, node):
        if mapper.kind == "Fn":
            return self.blame_function(mapper, node)
        if mapper.kind == "Ident":
            if mapper.name in SAFE_CALLS:
                return None
            fn = self.function_of(mapper)
            if fn is not None:
                return self.blame_function(fn, node)
        return node

    def function_of(self, ident):
        binding = ident.scope.lookup(ident.name) if ident.scope is not None else None
        if binding is None:
            return None
        if binding.kind == "fn":
            return binding.init
        if binding.kind == "var" and binding.init is not None and binding.init.kind == "Fn" and not binding.assigns:
            return binding.init
        return None

    def blame_function(self, fn, call):
        key = id(fn)
        if key in self.fn_results:
            result = self.fn_results[key]
            return call if result == "busy" else result
        self.fn_results[key] = "busy"
        result = None
        for ret in _returned(fn):
            result = self.blame(ret)
            if result is not None:
                break
        self.fn_results[key] = result
        return result

    # The walk over templates and sinks

    def _check_all(self):
        for name, tree in self.trees.items():
            for node in _walk(tree):
                if node.kind == "Tpl":
                    for expr in node.exprs:
                        self.count(expr)
                    if any(HTML_TEXT.search(p) for p in node.parts):
                        self.check_template(node, self.html)
                        self.check_attributes(node)
                sink = _sink_value(node)
                if sink is not None:
                    self.count(sink)
                    self.check_value(sink, self.sinks, frozenset())

    def count(self, node):
        """Counts allowlist uses at each value position of a ${...} or a sink's right-hand side."""
        file = self.file_of[id(node)]
        text = self.text(node)
        if text in self.allowed_texts.get(file, ()):
            self.counts[(file, text)] = self.counts.get((file, text), 0) + 1
            return
        for child in _value_positions(node):
            self.count(child)

    def check_template(self, tpl, out):
        if id(tpl) in self.seen_templates:
            return
        self.seen_templates.add(id(tpl))
        for expr in tpl.exprs:
            self.check_value(expr, out, frozenset())

    def check_value(self, node, out, narrowed):
        if self.is_allowed(node):
            return
        kind = node.kind
        if kind == "Tpl":
            # Reached through a value position, so it is HTML even without a tag.
            self.check_template(node, out)
        elif kind == "Cond":
            inner = narrowed
            if node.test.kind == "Call" and node.test.callee.kind == "Ident" and node.test.callee.name == "isNum" and node.test.args:
                inner = narrowed | {self.text(node.test.args[0])}
            self.check_value(node.a, out, inner)
            self.check_value(node.b, out, narrowed)
        elif kind == "Binary" and node.op in ("||", "??", "+"):
            self.check_value(node.left, out, narrowed)
            self.check_value(node.right, out, narrowed)
        elif kind == "Binary" and node.op == "&&":
            self.check_value(node.right, out, narrowed)
        else:
            b = self.blame(node, narrowed)
            if b is not None:
                finding = self.where(b)
                if finding not in out:
                    out.append(finding)

    def check_attributes(self, tpl):
        """An interpolation straight after name= with no quote can break out of the attribute."""
        in_tag, quote = False, None
        for index, part in enumerate(tpl.parts):
            for pos, c in enumerate(part):
                if quote:
                    if c == quote:
                        quote = None
                elif in_tag:
                    if c in "\"'":
                        quote = c
                    elif c == ">":
                        in_tag = False
                elif c == "<" and pos + 1 < len(part) and (part[pos + 1].isalpha() or part[pos + 1] in "!/"):
                    in_tag = True
            if index < len(tpl.exprs) and in_tag and quote is None and re.search(r"[\w-]=$", part):
                self.attrs.append(self.where(tpl.exprs[index]))


def _norm(text):
    return re.sub(r"\s+", " ", text).strip()


def _walk(node):
    yield node
    for child in node.children():
        yield from _walk(child)


def _returned(fn):
    """The value expressions a function can return (a bare return is undefined, which is harmless)."""
    if fn.body.kind != "Block":
        return [fn.body]
    found = []

    def visit(node):
        if node.kind == "Fn":
            return
        if node.kind == "Return":
            if node.arg is not None:
                found.append(node.arg)
            return
        for child in node.children():
            visit(child)

    visit(fn.body)
    return found


def _value_positions(node):
    if node.kind == "Cond":
        return [node.a, node.b]
    if node.kind == "Binary" and node.op in ("||", "??", "+"):
        return [node.left, node.right]
    if node.kind == "Binary" and node.op == "&&":
        return [node.right]
    return []


def _sink_value(node):
    """The HTML text given to a sink, or None when node is not a sink."""
    if node.kind == "Assign" and node.op in ("=", "+=") and node.target.kind == "Member" and node.target.prop in ("innerHTML", "outerHTML"):
        return node.value
    if node.kind == "Call" and node.callee.kind == "Member" and node.callee.prop == "insertAdjacentHTML" and len(node.args) > 1:
        return node.args[1]
    return None


# Values the proof above cannot see through. Keyed by file and the exact expression text, with the
# exact number of uses: a new ${html} cannot slip in under an old entry and a stale one cannot stay.
HTML_ALLOW = {
    ("app.js", "html"): (1, "fillTable parameter: every caller's row builder is itself checked"),
    ("app.js", "html ? value : escapeHtml(value)"): (1, "html is true only with barHtml output"),
    ("app.js", "text"): (1, "reading() returns escaped text or barHtml"),
    ("app.js", "noteHtml"): (1, "both callers escape"),
    ("app.js", 'SECTION_LINKS[id] || ""'): (1, "fixed strings"),
    ("app.js", 'rows.join("")'): (1, "array of checked templates"),
    ("app.js", 'buttons.join("")'): (1, "array of checked templates"),
    ("app.js", 'cards.slice(0, 6).join("")'): (1, "kpiCard results only"),
    ("app.js", "units[i]"): (2, "local array of fixed strings"),
    ("alerts.js", "html"): (2, "parameter: callers pass checked templates; Changed alerts: sections built from escaped lines"),
    ("alerts.js", 'rows.join("")'): (1, "array of checked templates"),
    ("alerts.js", 'lines.join("")'): (1, "Changed alerts: each line built by li(), which escapes every value"),
    ("availability.js", 'stripes.join("")'): (1, "array of checked templates"),
    ("adddevice.js", "snmpOnes"): (2, "built only from profileOptionsHtml, escaped when made"),
    ("setup.js", "snmpOnes"): (1, "built only from profileOptionsHtml, escaped when made"),
    ("setup.js", "attrs"): (1, "literal attribute text at the call sites"),
    ("setup.js", "extra"): (1, "literal attribute text at the call sites"),
    ("botcmds.js", "body"): (1, "callers pass checked templates"),
    ("guide.js", "await r.text()"): (1, "fixed /guide.html shipped with the app"),
    ("map.js", "MAP_ICONS[n.kind] || MAP_ICONS.other"): (1, "fixed SVG strings"),
    ("map.js", 'tags.join("")'): (1, "array built by mapPortTag, which escapes"),
    ("map.js", "MAP_ICONS.gateway"): (1, "fixed SVG string (the internet globe)"),
    ("map.js", "under"): (1, "built by mapInternet and mapWifiFan, which escape every value"),
    ("map.js", "html"): (1, "node and link templates, each value escaped, plus mapFlow, which escapes"),
    ("taxonomy.js", "pop.innerHTML"): (1, "a copy of DOM already rendered from tagChips"),
    ("updates.js", "inline(item[1])"): (1, "escapes first, then adds fixed tags"),
    ("updates.js", "inline(head[1])"): (1, "escapes first, then adds fixed tags"),
    ("updates.js", "inline(line)"): (1, "escapes first, then adds fixed tags"),
    ("workflows.js", "WF_KIND[n.type].badge"): (1, "fixed strings"),
    ("workflows.js", "WF_KIND[p.type].badge"): (1, "fixed strings"),
    ("workflows.js", "WF_KIND[pal.spec.type].badge"): (1, "fixed strings"),
}


def _load_web():
    sources = {}
    for path in sorted(glob.glob(os.path.join(_env.ROOT, "web", "*.js"))):
        with open(path, encoding="utf-8") as f:
            sources[os.path.basename(path)] = f.read()
    return sources


def _findings(src, name="t.js"):
    a = Analysis({name: src})
    return a.html + a.sinks


class EscapingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.web = Analysis(_load_web(), HTML_ALLOW)

    def test_every_html_interpolation_is_escaped(self):
        self.assertEqual(self.web.html, [])

    def test_every_sink_right_side_is_safe(self):
        self.assertEqual(self.web.sinks, [])

    def test_no_unquoted_attribute_values(self):
        self.assertEqual(self.web.attrs, [])

    def test_allowlist_counts_are_exact(self):
        wrong = {key: (n, self.web.counts.get((key[0], _norm(key[1])), 0))
                 for key, (n, _why) in HTML_ALLOW.items() if self.web.counts.get((key[0], _norm(key[1])), 0) != n}
        self.assertEqual(wrong, {})


class ScannerTests(unittest.TestCase):
    def test_raw_value_is_found(self):
        self.assertEqual(_findings('const r = data(); const h = `<td>${r.mtu ?? "-"}</td>`;'), ["t.js:1: r.mtu"])

    def test_escaped_and_number_pass(self):
        self.assertEqual(_findings('const h = `<td>${escapeHtml(x)}</td><td>${Number(y)}</td>`;'), [])

    def test_nested_template_is_checked(self):
        self.assertEqual(_findings('const h = `<a>${x ? `(${y})` : ""}</a>`;'), ["t.js:1: y"])

    def test_map_join_is_walked(self):
        self.assertEqual(_findings('const h = `<ul>${xs.map(a => `<li>${a.b}</li>`).join("")}</ul>`;'), ["t.js:1: a.b"])
        self.assertEqual(_findings('const h = `<ul>${xs.map(a => `<li>${escapeHtml(a.b)}</li>`).join("")}</ul>`;'), [])

    def test_ternary_checks_both_arms(self):
        self.assertEqual(_findings('const h = `<b>${c ? a : escapeHtml(b)}</b>`;'), ["t.js:1: a"])
        self.assertEqual(_findings('const h = `<b>${c ? escapeHtml(a) : b}</b>`;'), ["t.js:1: b"])

    def test_concat_checks_each_operand(self):
        self.assertEqual(_findings('const h = `<b>${"a" + x}</b>`;'), ["t.js:1: x"])

    def test_template_argument_is_left_to_the_helper(self):
        src = 'function h(v) { return `<i>${escapeHtml(v)}</i>`; }\nconst o = `<td>${h(`${a}`)}</td>`;'
        self.assertEqual(_findings(src), [])

    def test_helper_is_proved_from_its_body(self):
        src = 'function h(v) { return `<i>${escapeHtml(v)}</i>`; }\nconst o = `<td>${h(a)}</td>`;'
        self.assertEqual(_findings(src), [])

    def test_helper_leaking_a_parameter_is_found(self):
        src = 'function h(v) {\n  return `<i>${v}</i>`;\n}\nconst o = `<td>${h(a)}</td>`;'
        self.assertEqual(_findings(src), ["t.js:2: v"])

    def test_is_num_guard_narrows(self):
        self.assertEqual(_findings('const h = `<b>${isNum(a) ? a : ""}</b>`;'), [])
        self.assertEqual(_findings('const h = `<b>${isNum(a) ? b : ""}</b>`;'), ["t.js:1: b"])

    def test_bare_to_locale_string_is_found(self):
        self.assertEqual(_findings('const h = `<b>${x.toLocaleString()}</b>`;'), ["t.js:1: x.toLocaleString()"])
        self.assertEqual(_findings('const h = `<b>${Number(x).toLocaleString()}</b>`;'), [])

    def test_replace_keeps_only_what_is_safe(self):
        self.assertEqual(_findings('const h = `<b>${escapeHtml(a).replace(/x/g, "<i>")}</b>`;'), [])
        self.assertEqual(_findings('const h = `<b>${a.replace(/x/g, "<i>")}</b>`;'), ["t.js:1: a"])
        self.assertEqual(_findings('const h = `<b>${escapeHtml(a).replace(/x/g, b)}</b>`;'), ["t.js:1: b"])

    def test_sink_right_side_is_checked(self):
        self.assertEqual(_findings('el.innerHTML = a + "<b>";'), ["t.js:1: a"])
        self.assertEqual(_findings('el.insertAdjacentHTML("beforeend", escapeHtml(a));'), [])

    def test_scanner_survives_regex_comments_and_braces(self):
        src = ('const r = /`[/]`/g; // a ` in a comment\n'
               '/* and ` here */\n'
               'const n = a / b / c;\n'
               'const h = `<b>${xs.map(x => { const o = {k: 1}; return Number(o.k); }).join("")}</b><i>${y}</i>`;')
        self.assertEqual(_findings(src), ["t.js:4: y"])

    def test_local_names_resolve_by_scope(self):
        src = ('function one() { const stat = x => `<b>${escapeHtml(x)}</b>`; return `<i>${stat(1)}</i>`; }\n'
               'function two() { const stat = x => `<b>${x}</b>`; return `<i>${stat(1)}</i>`; }')
        self.assertEqual(_findings(src), ["t.js:2: x"])

    def test_helper_cycle_is_unsafe(self):
        src = 'function a() { return b(); }\nfunction b() { return a(); }\nconst h = `<b>${a()}</b>`;'
        self.assertEqual(len(_findings(src)), 1)

    def test_unquoted_attribute_is_found(self):
        a = Analysis({"t.js": 'const h = `<a href=${escapeHtml(u)}>x</a>`; const q = `<a href="/x?a=${Number(n)}">y</a>`;'})
        self.assertEqual(a.attrs, ["t.js:1: escapeHtml(u)"])


if __name__ == "__main__":
    unittest.main()
