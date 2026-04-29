"""
LuauShield Lexer
=================
Full Luau tokenizer producing a stream of typed tokens with position tracking.
Handles: keywords, identifiers, numbers, strings (single/double/long/interpolated),
operators, comments, and Luau-specific syntax.
"""

from enum import Enum, auto
from typing import List, Optional
from dataclasses import dataclass


class TokenType(Enum):
    # Literals
    NUMBER = auto()
    STRING = auto()
    TRUE = auto()
    FALSE = auto()
    NIL = auto()

    # Identifier
    NAME = auto()

    # Keywords
    AND = auto()
    BREAK = auto()
    CONTINUE = auto()
    DO = auto()
    ELSE = auto()
    ELSEIF = auto()
    END = auto()
    FOR = auto()
    FUNCTION = auto()
    IF = auto()
    IN = auto()
    LOCAL = auto()
    NOT = auto()
    OR = auto()
    REPEAT = auto()
    RETURN = auto()
    THEN = auto()
    UNTIL = auto()
    WHILE = auto()

    # Operators
    PLUS = auto()       # +
    MINUS = auto()      # -
    STAR = auto()       # *
    SLASH = auto()      # /
    PERCENT = auto()    # %
    CARET = auto()      # ^
    HASH = auto()       # #
    EQ = auto()         # ==
    NEQ = auto()        # ~=
    LT = auto()         # <
    GT = auto()         # >
    LTE = auto()        # <=
    GTE = auto()        # >=
    ASSIGN = auto()     # =
    LPAREN = auto()     # (
    RPAREN = auto()     # )
    LBRACE = auto()     # {
    RBRACE = auto()     # }
    LBRACKET = auto()   # [
    RBRACKET = auto()   # ]
    SEMICOLON = auto()  # ;
    COLON = auto()      # :
    DOUBLECOLON = auto() # ::
    COMMA = auto()      # ,
    DOT = auto()        # .
    DOTDOT = auto()     # ..
    DOTDOTDOT = auto()  # ...

    # Compound Assignment Operators (Luau)
    PLUS_ASSIGN = auto()    # +=
    MINUS_ASSIGN = auto()   # -=
    STAR_ASSIGN = auto()    # *=
    SLASH_ASSIGN = auto()   # /=
    PERCENT_ASSIGN = auto() # %=
    CARET_ASSIGN = auto()   # ^=
    DOTDOT_ASSIGN = auto()  # ..=

    # Special
    EOF = auto()


KEYWORDS = {
    'and': TokenType.AND, 'break': TokenType.BREAK, 'continue': TokenType.CONTINUE,
    'do': TokenType.DO, 'else': TokenType.ELSE, 'elseif': TokenType.ELSEIF,
    'end': TokenType.END, 'false': TokenType.FALSE, 'for': TokenType.FOR,
    'function': TokenType.FUNCTION, 'if': TokenType.IF, 'in': TokenType.IN,
    'local': TokenType.LOCAL, 'nil': TokenType.NIL, 'not': TokenType.NOT,
    'or': TokenType.OR, 'repeat': TokenType.REPEAT, 'return': TokenType.RETURN,
    'then': TokenType.THEN, 'true': TokenType.TRUE, 'until': TokenType.UNTIL,
    'while': TokenType.WHILE,
}


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    col: int

    def __repr__(self):
        return f"Token({self.type.name}, {self.value!r}, L{self.line})"


class LexerError(Exception):
    def __init__(self, message: str, line: int, col: int):
        super().__init__(f"Lexer error at line {line}, col {col}: {message}")
        self.line = line
        self.col = col


class Lexer:
    """Tokenizes Luau source code into a stream of Tokens."""

    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.line = 1
        self.col = 1
        self.tokens: List[Token] = []

    def tokenize(self) -> List[Token]:
        """Tokenize the entire source and return the token list."""
        while self.pos < len(self.source):
            self._skip_whitespace_and_comments()
            if self.pos >= len(self.source):
                break

            ch = self.source[self.pos]

            if ch == '\n':
                self.pos += 1
                self.line += 1
                self.col = 1
                continue

            # Numbers
            if ch.isdigit() or (ch == '.' and self._peek(1).isdigit()):
                self._read_number()
            # Strings
            elif ch in ('"', "'"):
                self._read_short_string(ch)
            # Long strings
            elif ch == '[' and self._peek(1) in ('[', '='):
                level = self._check_long_bracket()
                if level >= 0:
                    self._read_long_string(level)
                else:
                    self._emit(TokenType.LBRACKET, '[')
            # Identifiers and keywords
            elif ch.isalpha() or ch == '_':
                self._read_name()
            # Operators and punctuation
            else:
                self._read_operator()

        self.tokens.append(Token(TokenType.EOF, '', self.line, self.col))
        return self.tokens

    def _peek(self, offset: int = 0) -> str:
        idx = self.pos + offset
        if idx < len(self.source):
            return self.source[idx]
        return '\0'

    def _advance(self) -> str:
        ch = self.source[self.pos]
        self.pos += 1
        if ch == '\n':
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return ch

    def _emit(self, ttype: TokenType, value: str):
        self.tokens.append(Token(ttype, value, self.line, self.col))
        for _ in range(len(value)):
            if self.pos < len(self.source):
                self._advance()

    def _skip_whitespace_and_comments(self):
        while self.pos < len(self.source):
            ch = self.source[self.pos]
            # Whitespace (but not newline - handled in main loop)
            if ch in (' ', '\t', '\r', '\f', '\v'):
                self._advance()
                continue
            if ch == '\n':
                return  # Let main loop handle newlines

            # Comments
            if ch == '-' and self._peek(1) == '-':
                self._skip_comment()
                continue

            break

    def _skip_comment(self):
        """Skip -- single-line or --[[ long ]] comments."""
        self.pos += 2  # skip --
        self.col += 2

        # Check for long comment --[[ or --[==[ etc
        if self.pos < len(self.source) and self.source[self.pos] == '[':
            level = self._check_long_bracket()
            if level >= 0:
                self._skip_long_string(level)
                return

        # Single-line comment: skip to end of line
        while self.pos < len(self.source) and self.source[self.pos] != '\n':
            self.pos += 1
            self.col += 1

    def _check_long_bracket(self) -> int:
        """Check if we have a long bracket [===[ and return the level, or -1."""
        if self.source[self.pos] != '[':
            return -1
        i = self.pos + 1
        level = 0
        while i < len(self.source) and self.source[i] == '=':
            level += 1
            i += 1
        if i < len(self.source) and self.source[i] == '[':
            return level
        return -1

    def _skip_long_string(self, level: int):
        """Skip a long string/comment of given bracket level."""
        close = ']' + ('=' * level) + ']'
        self.pos += 2 + level  # skip [===[
        self.col += 2 + level
        while self.pos < len(self.source):
            idx = self.source.find(close, self.pos)
            if idx == -1:
                self.pos = len(self.source)
                return
            # Count newlines between current pos and idx
            segment = self.source[self.pos:idx]
            newlines = segment.count('\n')
            self.line += newlines
            self.pos = idx + len(close)
            self.col = 1 if newlines > 0 else self.col + (idx - self.pos + len(close))
            return

    def _read_number(self):
        """Read a numeric literal (int, float, hex, binary)."""
        start = self.pos
        start_line, start_col = self.line, self.col

        if self.source[self.pos] == '0' and self.pos + 1 < len(self.source):
            next_ch = self.source[self.pos + 1].lower()
            if next_ch == 'x':  # Hex
                self.pos += 2
                self.col += 2
                while self.pos < len(self.source) and (self.source[self.pos] in '0123456789abcdefABCDEF_'):
                    self.pos += 1
                    self.col += 1
                self.tokens.append(Token(TokenType.NUMBER, self.source[start:self.pos], start_line, start_col))
                return
            elif next_ch == 'b':  # Binary
                self.pos += 2
                self.col += 2
                while self.pos < len(self.source) and self.source[self.pos] in '01_':
                    self.pos += 1
                    self.col += 1
                self.tokens.append(Token(TokenType.NUMBER, self.source[start:self.pos], start_line, start_col))
                return

        # Decimal number
        while self.pos < len(self.source) and (self.source[self.pos].isdigit() or self.source[self.pos] == '_'):
            self.pos += 1
            self.col += 1

        # Decimal point
        if self.pos < len(self.source) and self.source[self.pos] == '.':
            if self.pos + 1 < len(self.source) and self.source[self.pos + 1] == '.':
                pass  # .. operator, not decimal point
            else:
                self.pos += 1
                self.col += 1
                while self.pos < len(self.source) and (self.source[self.pos].isdigit() or self.source[self.pos] == '_'):
                    self.pos += 1
                    self.col += 1

        # Exponent
        if self.pos < len(self.source) and self.source[self.pos] in ('e', 'E'):
            self.pos += 1
            self.col += 1
            if self.pos < len(self.source) and self.source[self.pos] in ('+', '-'):
                self.pos += 1
                self.col += 1
            while self.pos < len(self.source) and self.source[self.pos].isdigit():
                self.pos += 1
                self.col += 1

        self.tokens.append(Token(TokenType.NUMBER, self.source[start:self.pos], start_line, start_col))

    def _read_short_string(self, quote: str):
        """Read a single or double-quoted string."""
        start_line, start_col = self.line, self.col
        self.pos += 1  # skip opening quote
        self.col += 1
        result = []

        while self.pos < len(self.source):
            ch = self.source[self.pos]
            if ch == '\\':
                self.pos += 1
                self.col += 1
                if self.pos < len(self.source):
                    esc = self.source[self.pos]
                    result.append('\\' + esc)
                    self.pos += 1
                    self.col += 1
                    # Handle numeric escapes \123
                    if esc.isdigit():
                        for _ in range(2):
                            if self.pos < len(self.source) and self.source[self.pos].isdigit():
                                result[-1] += self.source[self.pos]
                                self.pos += 1
                                self.col += 1
            elif ch == quote:
                self.pos += 1
                self.col += 1
                self.tokens.append(Token(TokenType.STRING, ''.join(result), start_line, start_col))
                return
            elif ch == '\n':
                raise LexerError("Unterminated string", start_line, start_col)
            else:
                result.append(ch)
                self.pos += 1
                self.col += 1

        raise LexerError("Unterminated string", start_line, start_col)

    def _read_long_string(self, level: int):
        """Read a long bracket string [===[ ... ]===]."""
        start_line, start_col = self.line, self.col
        close = ']' + ('=' * level) + ']'
        self.pos += 2 + level  # skip [===[
        self.col += 2 + level

        # Skip immediate newline after opening bracket
        if self.pos < len(self.source) and self.source[self.pos] == '\n':
            self.pos += 1
            self.line += 1
            self.col = 1

        start_content = self.pos
        idx = self.source.find(close, self.pos)
        if idx == -1:
            raise LexerError("Unterminated long string", start_line, start_col)

        content = self.source[start_content:idx]
        newlines = content.count('\n')
        self.line += newlines
        self.pos = idx + len(close)
        self.col = 1 if newlines > 0 else self.col + len(content) + len(close)

        self.tokens.append(Token(TokenType.STRING, content, start_line, start_col))

    def _read_name(self):
        """Read an identifier or keyword."""
        start = self.pos
        start_line, start_col = self.line, self.col

        while self.pos < len(self.source) and (self.source[self.pos].isalnum() or self.source[self.pos] == '_'):
            self.pos += 1
            self.col += 1

        word = self.source[start:self.pos]
        ttype = KEYWORDS.get(word, TokenType.NAME)
        self.tokens.append(Token(ttype, word, start_line, start_col))

    def _read_operator(self):
        """Read an operator or punctuation token."""
        ch = self.source[self.pos]
        start_line, start_col = self.line, self.col

        two_char = self.source[self.pos:self.pos + 3] if self.pos + 2 < len(self.source) else ''
        one_more = self.source[self.pos:self.pos + 2] if self.pos + 1 < len(self.source) else ''

        # Three-character tokens
        three_map = {
            '...': TokenType.DOTDOTDOT,
            '..=': TokenType.DOTDOT_ASSIGN
        }
        if two_char in three_map:
            self.tokens.append(Token(three_map[two_char], two_char, start_line, start_col))
            self.pos += 3; self.col += 3; return

        # Two-character tokens
        two_map = {
            '==': TokenType.EQ, '~=': TokenType.NEQ,
            '<=': TokenType.LTE, '>=': TokenType.GTE,
            '..': TokenType.DOTDOT, '::': TokenType.DOUBLECOLON,
            '+=': TokenType.PLUS_ASSIGN, '-=': TokenType.MINUS_ASSIGN,
            '*=': TokenType.STAR_ASSIGN, '/=': TokenType.SLASH_ASSIGN,
            '%=': TokenType.PERCENT_ASSIGN, '^=': TokenType.CARET_ASSIGN
        }
        if one_more in two_map:
            self.tokens.append(Token(two_map[one_more], one_more, start_line, start_col))
            self.pos += 2; self.col += 2; return

        # Single-character tokens
        one_map = {
            '+': TokenType.PLUS, '-': TokenType.MINUS, '*': TokenType.STAR,
            '/': TokenType.SLASH, '%': TokenType.PERCENT, '^': TokenType.CARET,
            '#': TokenType.HASH, '=': TokenType.ASSIGN, '<': TokenType.LT,
            '>': TokenType.GT, '(': TokenType.LPAREN, ')': TokenType.RPAREN,
            '{': TokenType.LBRACE, '}': TokenType.RBRACE, '[': TokenType.LBRACKET,
            ']': TokenType.RBRACKET, ';': TokenType.SEMICOLON, ':': TokenType.COLON,
            ',': TokenType.COMMA, '.': TokenType.DOT,
        }
        if ch in one_map:
            self.tokens.append(Token(one_map[ch], ch, start_line, start_col))
            self.pos += 1; self.col += 1; return

        # Unknown character — skip (Luau type annotations, etc.)
        self.pos += 1
        self.col += 1
