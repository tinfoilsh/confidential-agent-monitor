package sentinel

deny contains sprintf("%s is not a configured connection", [input.tcp.host]) if {
	input.tcp
	not input.connection
}
