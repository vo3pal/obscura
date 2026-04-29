"""
LuauShield Globals Whitelist
=============================
Comprehensive list of Roblox/Luau globals that must NEVER be renamed.
Categorized by origin: Lua stdlib, Roblox engine, datatypes, services, task library.
"""

# ============================================================================
# LUA 5.1 STANDARD LIBRARY GLOBALS
# ============================================================================
LUA_STDLIB = frozenset({
    # Core functions
    "print", "warn", "error", "assert", "pcall", "xpcall",
    "type", "tostring", "tonumber", "rawget", "rawset", "rawequal", "rawlen",
    "select", "unpack", "next", "pairs", "ipairs",
    "require", "loadstring", "load", "dofile",
    "setmetatable", "getmetatable", "setfenv", "getfenv",
    "collectgarbage", "newproxy",

    # Libraries (as table names)
    "math", "string", "table", "coroutine", "os", "io", "debug",
    "bit32", "utf8", "buffer",
})

# ============================================================================
# ROBLOX ENGINE GLOBALS
# ============================================================================
ROBLOX_GLOBALS = frozenset({
    # Core singletons
    "game", "workspace", "script", "plugin",
    "_G", "shared",

    # Instance creation
    "Instance",

    # Special globals
    "typeof", "wait", "spawn", "delay", "tick", "time",
    "elapsedTime", "printidentity", "settings", "stats",
    "version", "UserSettings",

    # Task library
    "task",
})

# ============================================================================
# ROBLOX DATA TYPES (constructors)
# ============================================================================
ROBLOX_DATATYPES = frozenset({
    "Axes", "BrickColor", "CatalogSearchParams", "CFrame",
    "Color3", "ColorSequence", "ColorSequenceKeypoint",
    "Content", "DateTime", "DockWidgetPluginGuiInfo",
    "Enum", "Faces", "FloatCurveKey",
    "Font", "Instance", "NumberRange",
    "NumberSequence", "NumberSequenceKeypoint",
    "OverlapParams", "PathWaypoint", "PhysicalProperties",
    "Random", "Ray", "RaycastParams", "RaycastResult",
    "Rect", "Region3", "Region3int16",
    "RotationCurveKey", "SharedTable",
    "TweenInfo", "UDim", "UDim2",
    "Vector2", "Vector2int16", "Vector3", "Vector3int16",
})

# ============================================================================
# ROBLOX SERVICES (commonly accessed via GetService)
# ============================================================================
ROBLOX_SERVICES = frozenset({
    "AnalyticsService", "AssetService", "BadgeService",
    "Chat", "CollectionService", "ContentProvider",
    "ContextActionService", "DataStoreService", "Debris",
    "GamePassService", "GroupService", "GuiService",
    "HapticService", "HttpService", "InsertService",
    "KeyframeSequenceProvider", "Lighting", "LocalizationService",
    "LogService", "MarketplaceService", "MemoryStoreService",
    "MessagingService", "PathfindingService", "PhysicsService",
    "Players", "PolicyService", "ProximityPromptService",
    "ReplicatedFirst", "ReplicatedStorage", "RunService",
    "ScriptContext", "ServerScriptService", "ServerStorage",
    "SocialService", "SoundService", "StarterGui",
    "StarterPack", "StarterPlayer", "Stats",
    "Teams", "TeleportService", "TestService",
    "TextChatService", "TextService", "TweenService",
    "UserInputService", "VRService", "Workspace",
})

# ============================================================================
# ROBLOX ENUM ITEMS (commonly used directly)
# ============================================================================
ROBLOX_ENUMS = frozenset({
    "Enum",
})

# ============================================================================
# SPECIAL IDENTIFIERS (never rename in any context)
# ============================================================================
SPECIAL_IDENTIFIERS = frozenset({
    "self",       # Method context
    "true", "false", "nil",  # Literals (technically keywords)
    "and", "or", "not",       # Logical operators (keywords)
    "local", "function", "end", "if", "then", "else", "elseif",
    "while", "do", "for", "in", "repeat", "until", "return",
    "break", "continue",  # Luau has continue
})

# ============================================================================
# LUAU KEYWORDS (parser needs these, not for renaming logic since they can't be identifiers)
# ============================================================================
LUAU_KEYWORDS = frozenset({
    "and", "break", "continue", "do", "else", "elseif", "end",
    "false", "for", "function", "if", "in", "local", "nil",
    "not", "or", "repeat", "return", "then", "true", "until", "while",
})

# ============================================================================
# COMBINED WHITELIST — THE MASTER SET
# ============================================================================
NEVER_RENAME = (
    LUA_STDLIB
    | ROBLOX_GLOBALS
    | ROBLOX_DATATYPES
    | ROBLOX_SERVICES
    | ROBLOX_ENUMS
    | SPECIAL_IDENTIFIERS
)


def is_renameable(name: str) -> bool:
    """Check if an identifier is safe to rename (not in any whitelist)."""
    return name not in NEVER_RENAME


def is_keyword(name: str) -> bool:
    """Check if a string is a Luau keyword."""
    return name in LUAU_KEYWORDS


def is_roblox_service(name: str) -> bool:
    """Check if a name is a known Roblox service."""
    return name in ROBLOX_SERVICES


def is_lua_stdlib(name: str) -> bool:
    """Check if a name is a Lua standard library global."""
    return name in LUA_STDLIB
