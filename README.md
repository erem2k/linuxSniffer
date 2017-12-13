Server process will automatically daemonize on startup. You can use client process to communicate with server and pull stats.
On sniffer start server will attempt to read previous captured packet's data from locally created file. If file is invalid or cannot be opened, no stats are loaded.
On sniffer stop server will attempt to write stats to local file. 

Available client commands:
	start - Start sniffing packets from default or selected interface
	stop - Stop sniffing packets
	show [ip] count - Print received packet count from [ip] address
	select iface [iface] - Set interface for sniffing
	stat [iface] - Print all collected statistics for [iface]. If [iface] is omitted, stats for all interfaces are displayed
	--h - Show help