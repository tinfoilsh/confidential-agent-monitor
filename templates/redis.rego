package templates.redis

catalog := {
	"title": "Redis",
	"fields": [{"key": "url", "label": "URL", "hint": "rediss://user:password@host:6379", "secret": true}],
	"connections": {"": {"redis": {"$secret": "url"}}},
	"defaults": {"contents": "me", "strangers": true, "sends": "me"},
	"actions": {
		"read": {"title": "Read keys"},
		"write": {"title": "Change keys and the server", "save": "Allow {command}"},
	},
}

changes := {"write"}

needs_trust := {"write"}

argv := input.redis.argv

command := input.redis.command

reads := {
	"AUTH", "HELLO", "PING", "ECHO", "SELECT", "QUIT", "MULTI", "EXEC", "DISCARD", "WATCH", "UNWATCH",
	"SUBSCRIBE", "PSUBSCRIBE", "UNSUBSCRIBE", "PUNSUBSCRIBE", "INFO", "DBSIZE", "TIME",
	"COMMAND", "COMMAND|COUNT", "COMMAND|DOCS", "COMMAND|INFO", "COMMAND|LIST", "COMMAND|GETKEYS", "COMMAND|GETKEYSANDFLAGS",
	# Client libraries name their connection as they open it.
	"CLIENT|SETNAME", "CLIENT|SETINFO", "CLIENT|GETNAME", "CLIENT|ID", "CLIENT|INFO",
	"TYPE", "TTL", "PTTL", "EXISTS", "KEYS", "SCAN", "RANDOMKEY", "DUMP",
	"OBJECT|ENCODING", "OBJECT|FREQ", "OBJECT|IDLETIME", "OBJECT|REFCOUNT",
	"GET", "MGET", "GETRANGE", "STRLEN", "GETBIT", "BITCOUNT", "PFCOUNT",
	"HGET", "HMGET", "HGETALL", "HKEYS", "HVALS", "HLEN", "HEXISTS", "HSCAN",
	"LRANGE", "LLEN", "LINDEX", "LPOS", "SMEMBERS", "SISMEMBER", "SMISMEMBER", "SCARD", "SSCAN",
	"ZRANGE", "ZRANGEBYSCORE", "ZREVRANGE", "ZREVRANGEBYSCORE", "ZSCORE", "ZMSCORE", "ZCARD", "ZCOUNT",
	"ZRANK", "ZREVRANK", "ZSCAN", "XRANGE", "XREVRANGE", "XREAD", "XLEN",
	"XINFO|CONSUMERS", "XINFO|GROUPS", "XINFO|STREAM",
	"GEOPOS", "GEODIST", "GEOSEARCH",
}

read if command in reads

action := "read" if read

action := "write" if {
	input.redis
	not read
}

scope := {"command": command}

title := concat(" ", array.slice(argv, 0, 2))
