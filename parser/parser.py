"""
LuauShield Parser
==================
Recursive-descent parser: token stream → AST.
Handles all common Luau constructs. Gracefully skips type annotations.
"""

from typing import List, Optional
from .lexer import Token, TokenType, Lexer
from .ast_nodes import *


class ParseError(Exception):
    def __init__(self, message: str, token: Token):
        super().__init__(f"Parse error at line {token.line}, col {token.col}: {message} (got {token.type.name} '{token.value}')")
        self.token = token


class Parser:
    """Recursive-descent Luau parser."""

    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    @classmethod
    def from_source(cls, source: str) -> 'Parser':
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        return cls(tokens)

    def parse(self) -> Block:
        block = self._parse_block()
        self._expect(TokenType.EOF)
        return block

    # --- Token helpers ---

    def _current(self) -> Token:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else self.tokens[-1]

    def _peek(self, offset: int = 0) -> Token:
        idx = self.pos + offset
        return self.tokens[idx] if idx < len(self.tokens) else self.tokens[-1]

    def _check(self, *types: TokenType) -> bool:
        return self._current().type in types

    def _match(self, *types: TokenType) -> Optional[Token]:
        if self._current().type in types:
            tok = self._current()
            self.pos += 1
            return tok
        return None

    def _expect(self, ttype: TokenType) -> Token:
        tok = self._current()
        if tok.type != ttype:
            raise ParseError(f"Expected {ttype.name}", tok)
        self.pos += 1
        return tok

    def _skip_type_annotation(self):
        """Skip Luau type annotations like : Type, :: Type, <T>."""
        if self._check(TokenType.COLON) and not self._check(TokenType.DOUBLECOLON):
            self.pos += 1
            self._skip_type_expr()

    def _skip_type_expr(self):
        """Skip a type expression (basic heuristic)."""
        depth = 0
        while self.pos < len(self.tokens):
            t = self._current()
            if t.type == TokenType.LT:
                depth += 1
                self.pos += 1
            elif t.type == TokenType.GT and depth > 0:
                depth -= 1
                self.pos += 1
            elif depth == 0 and t.type in (
                TokenType.ASSIGN, TokenType.RPAREN, TokenType.COMMA,
                TokenType.EOF, TokenType.THEN, TokenType.DO,
                TokenType.END, TokenType.SEMICOLON, TokenType.RBRACE,
            ):
                return
            elif t.type == TokenType.NAME or t.type == TokenType.NIL or t.type == TokenType.DOT or t.type == TokenType.LBRACE or t.type == TokenType.RBRACE or t.type == TokenType.LPAREN or t.type == TokenType.RPAREN or t.type == TokenType.DOTDOTDOT or t.type == TokenType.COLON:
                self.pos += 1
            elif t.type == TokenType.STRING:
                self.pos += 1
            else:
                return

    # --- Block parsing ---

    def _parse_block(self) -> Block:
        block = Block(line=self._current().line, col=self._current().col)
        while True:
            self._skip_semicolons()
            if self._is_block_end():
                break
            stmt = self._parse_statement()
            if stmt:
                block.body.append(stmt)
        return block

    def _is_block_end(self) -> bool:
        return self._check(
            TokenType.EOF, TokenType.END, TokenType.ELSE,
            TokenType.ELSEIF, TokenType.UNTIL
        )

    def _skip_semicolons(self):
        while self._match(TokenType.SEMICOLON):
            pass

    # --- Statement parsing ---

    def _parse_statement(self) -> Optional[Node]:
        t = self._current()

        if t.type == TokenType.LOCAL:
            return self._parse_local()
        elif t.type == TokenType.FUNCTION:
            return self._parse_function_decl(is_local=False)
        elif t.type == TokenType.IF:
            return self._parse_if()
        elif t.type == TokenType.WHILE:
            return self._parse_while()
        elif t.type == TokenType.FOR:
            return self._parse_for()
        elif t.type == TokenType.REPEAT:
            return self._parse_repeat()
        elif t.type == TokenType.DO:
            return self._parse_do_block()
        elif t.type == TokenType.RETURN:
            return self._parse_return()
        elif t.type == TokenType.BREAK:
            self.pos += 1
            return BreakStatement(line=t.line, col=t.col)
        elif t.type == TokenType.CONTINUE:
            self.pos += 1
            return ContinueStatement(line=t.line, col=t.col)
        else:
            return self._parse_expr_or_assign()

    def _parse_local(self) -> Node:
        tok = self._expect(TokenType.LOCAL)

        # local function name(...)
        if self._check(TokenType.FUNCTION):
            return self._parse_function_decl(is_local=True)

        # local name, name, ... = expr, expr, ...
        names = [self._expect(TokenType.NAME).value]
        # Skip optional type annotation
        self._skip_type_annotation()

        while self._match(TokenType.COMMA):
            names.append(self._expect(TokenType.NAME).value)
            self._skip_type_annotation()

        values = []
        if self._match(TokenType.ASSIGN):
            values = self._parse_expr_list()

        return LocalStatement(line=tok.line, col=tok.col, names=names, values=values)

    def _parse_function_decl(self, is_local: bool = False) -> FunctionDecl:
        tok = self._expect(TokenType.FUNCTION)

        # Parse function name
        name_node: Node = Identifier(name=self._expect(TokenType.NAME).value, line=tok.line, col=tok.col)

        if not is_local:
            # Handle dotted names: a.b.c
            while self._match(TokenType.DOT):
                member = self._expect(TokenType.NAME).value
                name_node = MemberExpr(object=name_node, member=member, line=tok.line, col=tok.col)
            # Handle method name: a:b
            if self._match(TokenType.COLON):
                method = self._expect(TokenType.NAME).value
                name_node = MethodCall(object=name_node, method=method, args=[], line=tok.line, col=tok.col)

        # Skip generic type params <T, U>
        if self._check(TokenType.LT):
            self.pos += 1
            depth = 1
            while depth > 0 and self.pos < len(self.tokens):
                if self._current().type == TokenType.LT:
                    depth += 1
                elif self._current().type == TokenType.GT:
                    depth -= 1
                self.pos += 1

        params, has_vararg = self._parse_params()
        # Skip return type annotation
        if self._check(TokenType.COLON):
            self.pos += 1
            self._skip_type_expr()
        body = self._parse_block()
        self._expect(TokenType.END)

        return FunctionDecl(
            name=name_node, params=params, has_vararg=has_vararg,
            body=body, is_local=is_local, line=tok.line, col=tok.col
        )

    def _parse_params(self):
        """Parse function parameters. Returns (param_names, has_vararg)."""
        self._expect(TokenType.LPAREN)
        params = []
        has_vararg = False

        if not self._check(TokenType.RPAREN):
            if self._check(TokenType.DOTDOTDOT):
                self.pos += 1
                has_vararg = True
            else:
                params.append(self._expect(TokenType.NAME).value)
                self._skip_type_annotation()

                while self._match(TokenType.COMMA):
                    if self._check(TokenType.DOTDOTDOT):
                        self.pos += 1
                        has_vararg = True
                        break
                    params.append(self._expect(TokenType.NAME).value)
                    self._skip_type_annotation()

        self._expect(TokenType.RPAREN)
        return params, has_vararg

    def _parse_if(self) -> IfStatement:
        tok = self._expect(TokenType.IF)
        condition = self._parse_expression()
        self._expect(TokenType.THEN)
        body = self._parse_block()

        elseif_clauses = []
        while self._match(TokenType.ELSEIF):
            ei_cond = self._parse_expression()
            self._expect(TokenType.THEN)
            ei_body = self._parse_block()
            elseif_clauses.append(ElseIfClause(
                condition=ei_cond, body=ei_body,
                line=ei_cond.line, col=ei_cond.col
            ))

        else_body = None
        if self._match(TokenType.ELSE):
            else_body = self._parse_block()

        self._expect(TokenType.END)
        return IfStatement(
            condition=condition, body=body,
            elseif_clauses=elseif_clauses, else_body=else_body,
            line=tok.line, col=tok.col
        )

    def _parse_while(self) -> WhileLoop:
        tok = self._expect(TokenType.WHILE)
        condition = self._parse_expression()
        self._expect(TokenType.DO)
        body = self._parse_block()
        self._expect(TokenType.END)
        return WhileLoop(condition=condition, body=body, line=tok.line, col=tok.col)

    def _parse_for(self) -> Node:
        tok = self._expect(TokenType.FOR)
        name = self._expect(TokenType.NAME).value

        if self._match(TokenType.ASSIGN):
            # Numeric for: for i = start, stop[, step]
            start = self._parse_expression()
            self._expect(TokenType.COMMA)
            stop = self._parse_expression()
            step = None
            if self._match(TokenType.COMMA):
                step = self._parse_expression()
            self._expect(TokenType.DO)
            body = self._parse_block()
            self._expect(TokenType.END)
            return NumericFor(
                var_name=name, start=start, stop=stop, step=step,
                body=body, line=tok.line, col=tok.col
            )
        else:
            # Generic for: for k, v in expr do
            names = [name]
            # Skip type annotation on first name
            self._skip_type_annotation()
            while self._match(TokenType.COMMA):
                names.append(self._expect(TokenType.NAME).value)
                self._skip_type_annotation()
            self._expect(TokenType.IN)
            iterators = self._parse_expr_list()
            self._expect(TokenType.DO)
            body = self._parse_block()
            self._expect(TokenType.END)
            return GenericFor(
                names=names, iterators=iterators,
                body=body, line=tok.line, col=tok.col
            )

    def _parse_repeat(self) -> RepeatUntil:
        tok = self._expect(TokenType.REPEAT)
        body = self._parse_block()
        self._expect(TokenType.UNTIL)
        condition = self._parse_expression()
        return RepeatUntil(body=body, condition=condition, line=tok.line, col=tok.col)

    def _parse_do_block(self) -> DoBlock:
        tok = self._expect(TokenType.DO)
        body = self._parse_block()
        self._expect(TokenType.END)
        return DoBlock(body=body, line=tok.line, col=tok.col)

    def _parse_return(self) -> ReturnStatement:
        tok = self._expect(TokenType.RETURN)
        values = []
        if not self._is_block_end() and not self._check(TokenType.SEMICOLON):
            values = self._parse_expr_list()
        return ReturnStatement(values=values, line=tok.line, col=tok.col)

    # --- Expression / Assignment parsing ---

    def _parse_expr_or_assign(self) -> Node:
        """Parse an expression statement or assignment."""
        expr = self._parse_suffixed_expr()

        # Handle Luau compound assignments (desugar: expr += val -> expr = expr + val)
        compound_map = {
            TokenType.PLUS_ASSIGN: '+',
            TokenType.MINUS_ASSIGN: '-',
            TokenType.STAR_ASSIGN: '*',
            TokenType.SLASH_ASSIGN: '/',
            TokenType.PERCENT_ASSIGN: '%',
            TokenType.CARET_ASSIGN: '^',
            TokenType.DOTDOT_ASSIGN: '..'
        }

        if self._current().type in compound_map:
            op = compound_map[self._current().type]
            self.pos += 1
            value = self._parse_expression()
            
            desugared_value = BinaryOp(
                op=op, left=expr, right=value,
                line=expr.line, col=expr.col
            )
            return AssignStatement(
                targets=[expr], values=[desugared_value],
                line=expr.line, col=expr.col
            )

        # Check for assignment: expr, expr = expr, expr
        if self._check(TokenType.ASSIGN, TokenType.COMMA):
            targets = [expr]
            while self._match(TokenType.COMMA):
                targets.append(self._parse_suffixed_expr())
            self._expect(TokenType.ASSIGN)
            values = self._parse_expr_list()
            return AssignStatement(
                targets=targets, values=values,
                line=expr.line, col=expr.col
            )

        return ExpressionStatement(expression=expr, line=expr.line, col=expr.col)

    def _parse_expr_list(self) -> List[Node]:
        exprs = [self._parse_expression()]
        while self._match(TokenType.COMMA):
            exprs.append(self._parse_expression())
        return exprs

    # --- Expression parsing (precedence climbing) ---

    def _parse_expression(self) -> Node:
        return self._parse_or()

    def _parse_or(self) -> Node:
        left = self._parse_and()
        while self._match(TokenType.OR):
            right = self._parse_and()
            left = BinaryOp(op='or', left=left, right=right, line=left.line, col=left.col)
        return left

    def _parse_and(self) -> Node:
        left = self._parse_comparison()
        while self._match(TokenType.AND):
            right = self._parse_comparison()
            left = BinaryOp(op='and', left=left, right=right, line=left.line, col=left.col)
        return left

    def _parse_comparison(self) -> Node:
        left = self._parse_concat()
        while self._check(TokenType.LT, TokenType.GT, TokenType.LTE, TokenType.GTE,
                          TokenType.EQ, TokenType.NEQ):
            op_tok = self._current()
            self.pos += 1
            right = self._parse_concat()
            left = BinaryOp(op=op_tok.value, left=left, right=right, line=left.line, col=left.col)
        return left

    def _parse_concat(self) -> Node:
        left = self._parse_addition()
        if self._match(TokenType.DOTDOT):
            right = self._parse_concat()  # Right-associative
            left = BinaryOp(op='..', left=left, right=right, line=left.line, col=left.col)
        return left

    def _parse_addition(self) -> Node:
        left = self._parse_multiplication()
        while self._check(TokenType.PLUS, TokenType.MINUS):
            op_tok = self._current()
            self.pos += 1
            right = self._parse_multiplication()
            left = BinaryOp(op=op_tok.value, left=left, right=right, line=left.line, col=left.col)
        return left

    def _parse_multiplication(self) -> Node:
        left = self._parse_unary()
        while self._check(TokenType.STAR, TokenType.SLASH, TokenType.PERCENT):
            op_tok = self._current()
            self.pos += 1
            right = self._parse_unary()
            left = BinaryOp(op=op_tok.value, left=left, right=right, line=left.line, col=left.col)
        return left

    def _parse_unary(self) -> Node:
        if self._check(TokenType.MINUS):
            tok = self._current()
            self.pos += 1
            operand = self._parse_unary()
            return UnaryOp(op='-', operand=operand, line=tok.line, col=tok.col)
        if self._check(TokenType.NOT):
            tok = self._current()
            self.pos += 1
            operand = self._parse_unary()
            return UnaryOp(op='not', operand=operand, line=tok.line, col=tok.col)
        if self._check(TokenType.HASH):
            tok = self._current()
            self.pos += 1
            operand = self._parse_unary()
            return UnaryOp(op='#', operand=operand, line=tok.line, col=tok.col)
        return self._parse_power()

    def _parse_power(self) -> Node:
        base = self._parse_suffixed_expr()
        if self._match(TokenType.CARET):
            exp = self._parse_unary()  # Right-associative
            base = BinaryOp(op='^', left=base, right=exp, line=base.line, col=base.col)
        return base

    def _parse_suffixed_expr(self) -> Node:
        """Parse a primary expression followed by suffixes (.member, [index], (args), :method(args))."""
        expr = self._parse_primary()

        while True:
            if self._match(TokenType.DOT):
                member = self._expect(TokenType.NAME).value
                expr = MemberExpr(object=expr, member=member, line=expr.line, col=expr.col)
            elif self._check(TokenType.LBRACKET):
                self.pos += 1
                index = self._parse_expression()
                self._expect(TokenType.RBRACKET)
                expr = IndexExpr(object=expr, index=index, line=expr.line, col=expr.col)
            elif self._check(TokenType.COLON):
                # Check this is a method call, not a type annotation
                if self._peek(1).type == TokenType.NAME and self._peek(2).type == TokenType.LPAREN:
                    self.pos += 1  # skip :
                    method = self._expect(TokenType.NAME).value
                    args = self._parse_call_args()
                    expr = MethodCall(object=expr, method=method, args=args, line=expr.line, col=expr.col)
                elif self._peek(1).type == TokenType.NAME and self._peek(2).type == TokenType.LBRACE:
                    self.pos += 1
                    method = self._expect(TokenType.NAME).value
                    args = [self._parse_table_constructor()]
                    expr = MethodCall(object=expr, method=method, args=args, line=expr.line, col=expr.col)
                elif self._peek(1).type == TokenType.NAME and self._peek(2).type == TokenType.STRING:
                    self.pos += 1
                    method = self._expect(TokenType.NAME).value
                    s = self._current()
                    self.pos += 1
                    args = [StringLiteral(value=s.value, line=s.line, col=s.col)]
                    expr = MethodCall(object=expr, method=method, args=args, line=expr.line, col=expr.col)
                else:
                    break
            elif self._check(TokenType.LPAREN):
                args = self._parse_call_args()
                expr = FunctionCall(func=expr, args=args, line=expr.line, col=expr.col)
            elif self._check(TokenType.LBRACE):
                tbl = self._parse_table_constructor()
                expr = FunctionCall(func=expr, args=[tbl], line=expr.line, col=expr.col)
            elif self._check(TokenType.STRING):
                s = self._current()
                self.pos += 1
                expr = FunctionCall(
                    func=expr,
                    args=[StringLiteral(value=s.value, line=s.line, col=s.col)],
                    line=expr.line, col=expr.col
                )
            else:
                break

        return expr

    def _parse_call_args(self) -> List[Node]:
        """Parse (arg1, arg2, ...)."""
        self._expect(TokenType.LPAREN)
        args = []
        if not self._check(TokenType.RPAREN):
            args = self._parse_expr_list()
        self._expect(TokenType.RPAREN)
        return args

    def _parse_primary(self) -> Node:
        """Parse a primary expression: literal, name, or parenthesized expr."""
        t = self._current()

        if t.type == TokenType.NAME:
            self.pos += 1
            return Identifier(name=t.value, line=t.line, col=t.col)

        if t.type == TokenType.NUMBER:
            self.pos += 1
            return NumberLiteral(value=t.value, raw=t.value, line=t.line, col=t.col)

        if t.type == TokenType.STRING:
            self.pos += 1
            return StringLiteral(value=t.value, line=t.line, col=t.col)

        if t.type == TokenType.TRUE:
            self.pos += 1
            return BooleanLiteral(value=True, line=t.line, col=t.col)

        if t.type == TokenType.FALSE:
            self.pos += 1
            return BooleanLiteral(value=False, line=t.line, col=t.col)

        if t.type == TokenType.NIL:
            self.pos += 1
            return NilLiteral(line=t.line, col=t.col)

        if t.type == TokenType.DOTDOTDOT:
            self.pos += 1
            return VarargExpr(line=t.line, col=t.col)

        if t.type == TokenType.FUNCTION:
            return self._parse_function_expr()

        if t.type == TokenType.LBRACE:
            return self._parse_table_constructor()

        if t.type == TokenType.LPAREN:
            self.pos += 1
            expr = self._parse_expression()
            self._expect(TokenType.RPAREN)
            return ParenExpr(expression=expr, line=t.line, col=t.col)

        raise ParseError("Unexpected token", t)

    def _parse_function_expr(self) -> FunctionExpr:
        """Parse function(...) ... end (anonymous)."""
        tok = self._expect(TokenType.FUNCTION)
        params, has_vararg = self._parse_params()
        # Skip return type annotation
        if self._check(TokenType.COLON):
            self.pos += 1
            self._skip_type_expr()
        body = self._parse_block()
        self._expect(TokenType.END)
        return FunctionExpr(params=params, has_vararg=has_vararg, body=body, line=tok.line, col=tok.col)

    def _parse_table_constructor(self) -> TableConstructor:
        """Parse { field1, field2, ... }."""
        tok = self._expect(TokenType.LBRACE)
        fields = []

        while not self._check(TokenType.RBRACE):
            if self._check(TokenType.LBRACKET):
                # [expr] = expr
                self.pos += 1
                key = self._parse_expression()
                self._expect(TokenType.RBRACKET)
                self._expect(TokenType.ASSIGN)
                value = self._parse_expression()
                fields.append(TableField(key=key, value=value, is_bracket_key=True, line=key.line, col=key.col))
            elif self._check(TokenType.NAME) and self._peek(1).type == TokenType.ASSIGN:
                # name = expr
                name_tok = self._expect(TokenType.NAME)
                self._expect(TokenType.ASSIGN)
                value = self._parse_expression()
                key = StringLiteral(value=name_tok.value, line=name_tok.line, col=name_tok.col)
                fields.append(TableField(key=key, value=value, is_bracket_key=False, line=name_tok.line, col=name_tok.col))
            else:
                # positional value
                value = self._parse_expression()
                fields.append(TableField(key=None, value=value, line=value.line, col=value.col))

            if not self._match(TokenType.COMMA) and not self._match(TokenType.SEMICOLON):
                break

        self._expect(TokenType.RBRACE)
        return TableConstructor(fields=fields, line=tok.line, col=tok.col)
