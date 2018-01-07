#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <syslog.h>
#include <stdbool.h>
#include <inttypes.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <pthread.h>
#include <ds.h>

const char *statsFile = "./snifferStats.dat";
struct deviceStat_t *deviceStats = NULL;
int deviceCount = 0, selDeviceIndex = 0;

int initPipe[2];

bool sniffingFlag = false;
bool shutdownFlag = false;

pthread_t handleRequestsThread;

pthread_mutex_t mu_deviceStats = PTHREAD_MUTEX_INITIALIZER;
//Covers usage of selDeviceIndex, deviceCount and deviceStats itself, since they are always used together
pthread_mutex_t mu_isSniffing = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mu_isShutdown = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mu_statsFile = PTHREAD_MUTEX_INITIALIZER;

/*Data structures*/
struct ipStat_t {
	in_addr_t  ip;
	int packetCount;
};

struct deviceStat_t {
	char deviceName[16];
        AVLTREE ipTree;
	int ipCount;
};


/*Utility functions*/
bool writeWrap(int fd, const char* data, size_t dataSize)
{
	int bytesWritten = write(fd, data, dataSize);
	if (bytesWritten != dataSize) {
		if (bytesWritten > 0) 
			return 0;
		else {
			perror("Client: Socket write error");
			exit(-1);
		}
	}
	return 1;
}

bool isSniffing()
{
	bool status;
	
	pthread_mutex_lock(&mu_isSniffing);
	status = sniffingFlag;
	pthread_mutex_unlock(&mu_isSniffing);
	
	return status;
}

bool isShutdown()
{
	bool status;
	
	pthread_mutex_lock(&mu_isShutdown);
	status = shutdownFlag;
	pthread_mutex_unlock(&mu_isShutdown);
	
	return status;
}

int cmp_ipStat(DSKEY a, DSKEY b)
{
        return (a < b)? -1 : (a > b) ? 1 : 0 ;
}		

void freeNodeData(void* entry_data)
{
    free(entry_data);
}

/*Client-server query functions*/
void sendStatsOnIface(int fd, int index)
{
	char *returnString;
	
	pthread_mutex_lock(&mu_deviceStats);	
	
	if (index == -1) {
		int totalIps = 0;
		for (int i = 0; i < deviceCount; i++)
			totalIps += deviceStats[i].ipCount;
		returnString = (char*) calloc(18 * deviceCount 
			+ (16 + 4 + 17 + 8) * totalIps, sizeof(char)); //Size of device header line * devices + size of ip line * total ips
		
		for (int i = 0; i < deviceCount; i++) {
			if (i == 0)
				strcpy(returnString, deviceStats[i].deviceName);
			else
				strcat(returnString, deviceStats[i].deviceName);
			strcat(returnString, ":\n");
			for (struct ipStat_t* entry = (struct ipStat_t*) avlFirst(deviceStats[i].ipTree); entry; entry = (struct ipStat_t*) avlNext(deviceStats[i].ipTree)) {
				char snum[16];
				struct in_addr src;
				src.s_addr = entry->ip;
				strcat(returnString, inet_ntoa(src));
				strcat(returnString, " : Packets received ");
				sprintf(snum, "%d", entry->packetCount);
				strcat(returnString, snum);
				strcat(returnString, "\n");	
			}
		}
	}
	else if (index < deviceCount) {

		returnString = (char*) calloc((18)
			+ (16 + 4 + 17 + 8) * deviceStats[index].ipCount, sizeof(char)); //Size of device header line + size of ip line * ip count
		
		strcpy(returnString, deviceStats[index].deviceName);

		strcat(returnString, ":\n");
		for (struct ipStat_t* entry = (struct ipStat_t*) avlFirst(deviceStats[index].ipTree); entry; entry = (struct ipStat_t*) avlNext(deviceStats[index].ipTree)) {
			 char snum[16];
			 struct in_addr src;
			 src.s_addr = entry->ip;
			 strcat(returnString, inet_ntoa(src));
			 strcat(returnString, " : Packets received ");
			 sprintf(snum, "%d", entry->packetCount);
			 strcat(returnString, snum);
			 strcat(returnString, "\n");	
		 }                		
	}
	else {
		returnString = (char*) malloc(sizeof("Interface not found!\n"));
		returnString = "Interface not found!\n";
	}
	
	pthread_mutex_unlock(&mu_deviceStats);
		
	if (!writeWrap(fd, returnString, strlen(returnString) + 1))
		syslog (LOG_WARNING, "Server: Partial write to socket");
	
	free(returnString);
}

void sendStats(int fd)
{
    return sendStatsOnIface(fd, -1);
}

void sendIpStats(char * ip, int fd)
{
	struct in_addr requestedIp;
	requestedIp.s_addr = inet_addr(ip);
	int index = 0;
	
	if (requestedIp.s_addr == -1) {
		if (!writeWrap(fd, "Incorrect IP entered\n", sizeof(char) * strlen("Incorrect IP entered\n")))
			syslog (LOG_WARNING, "Server: Partial write to socket");		
		return;
	}
	
	struct ipStat_t* foundNode = (struct ipStat_t*) avlFind(deviceStats[selDeviceIndex].ipTree, (DSKEY) requestedIp.s_addr);
	
	if (foundNode) {
		char *returnString = (char*) malloc((23 + strlen(ip) + 8) * sizeof(char)); //Text + IP + Packet count
		
		pthread_mutex_lock(&mu_deviceStats);
		sprintf (returnString, "IP:%s\nPackets Received:%d\n", ip, foundNode->packetCount);
		
		pthread_mutex_unlock(&mu_deviceStats);
		
		if (!writeWrap(fd, returnString, strlen(returnString)))
			syslog (LOG_WARNING, "Server: Partial write to socket");
		free (returnString);
	}
	else
		if (!writeWrap(fd, "Requested IP wasn't found\n", sizeof("Requested IP wasn't found\n")))
			syslog (LOG_WARNING, "Server: Partial write to socket");
	
}

/*Daemon-related functions*/
static void daemonShutdown()
{
	//End sniffer thread
	pthread_mutex_lock(&mu_isShutdown);
	shutdownFlag = true;
	pthread_mutex_unlock(&mu_isShutdown);
	
	pthread_join(handleRequestsThread, NULL);
	
	pthread_mutex_lock(&mu_deviceStats);
	for (int i = 0; i < deviceCount; i++)
		avlCloseWithFunction(deviceStats[i].ipTree, freeNodeData);
	free(deviceStats);
	pthread_mutex_unlock(&mu_deviceStats);
	
	closelog();
}

static void signal_handler(int sig)
{
	switch(sig)
	{
		case SIGHUP:
			syslog(LOG_WARNING, "Server: Received SIGHUP signal.");
			break;
		case SIGINT:
		case SIGTERM:
			syslog(LOG_NOTICE, "Server: Daemon exiting");
			daemonShutdown();
			exit(EXIT_SUCCESS);
			break;
		default:
			syslog(LOG_WARNING, "Server: Unhandled signal %s", strsignal(sig));
			break;
	}
}

static void daemonize()
{
    pid_t pid;

    /* Fork off the parent process */
    pid = fork();

    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    /* Catch, ignore and handle signals */
	signal(SIGINT, signal_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGTERM, signal_handler);

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");

    /* Close all open file descriptors */
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        close (x);
    }

    openlog ("sniffer_daemon", LOG_PID, LOG_DAEMON);
}

/*File I/O*/
static bool readStats()
{
	pthread_mutex_lock(&mu_statsFile);
	//Heavily relies on file structure being correct
	FILE* fp = fopen(statsFile, "r");
	char buf[256];
	int devices = 0, ips = 0, devicesRead = 0;
	
	pthread_mutex_unlock(&mu_statsFile);	
	
	syslog (LOG_NOTICE, "Server: Attempting to read statistics from file");
	
	if (!fp) {
		syslog (LOG_CRIT, "Server: Unable to open statistics file");
		return false;
	}
	
	//Reading header
	fgets(buf, 256, fp);
	buf[strcspn(buf, "\n")] = 0;
	
	if (strcmp(buf, "#stat_head_begin") != 0) {
		syslog (LOG_CRIT, "Server: Can't recognize stats file header; Nothing read");
		return false;		
	}
	else
	{            				
		fgets(buf, 256, fp); //Gets device_count string
		buf[strcspn(buf, "\n")] = 0;
		strtok(buf, "=");
		devices = atoi(strtok(NULL, "="));
		
		if (devices <= 0)
			return false;
        
		//Lock once actual operations on shared memory are executed
		pthread_mutex_lock(&mu_deviceStats);
		
		deviceStats = (struct deviceStat_t*) malloc(sizeof(struct deviceStat_t) * devices);
		
		for (int i = 0; i < devices; i++) {
			char * tokP;
			fgets(buf, 256, fp);
			buf[strcspn(buf, "\n")] = 0;
			tokP = strtok(buf, " :");
			
			strcpy(deviceStats[i].deviceName, tokP);
			tokP = strtok(NULL, " :");
			deviceStats[i].ipCount = atoi(tokP);
		}
		
		fgets(buf, 256, fp);
		buf[strcspn(buf, "\n")] = 0;		
		
		if (strcmp(buf, "#stat_head_end") != 0)
			syslog (LOG_WARNING, "Server: Couldn't find file header closure");
		
		deviceCount = devices;
	}
	
	while (fgets(buf, 256, fp) != NULL) {	//Processes each device's IPs
		buf[strcspn(buf, "\n")] = 0;
		deviceStats[devicesRead].ipTree = avlNewTree(cmp_ipStat, 0, sizeof(in_addr_t));
		
		for (int i = 0; i < deviceStats[devicesRead].ipCount; i++) {
			char *tokP;
			struct ipStat_t* ipEntry = calloc(1, sizeof(struct ipStat_t));
			fgets(buf, 256, fp);
			buf[strcspn(buf, "\n")] = 0;
			tokP = strtok(buf, " :");
			sscanf(tokP, "%"SCNu32, &ipEntry->ip);
			tokP = strtok(NULL, " :");
			ipEntry->packetCount = atoi(tokP);
			avlAdd(deviceStats[devicesRead].ipTree, ipEntry->ip, (void*) ipEntry);
		}

		devicesRead++;
	}
	syslog (LOG_NOTICE, "Server: Statistics file read complete");
	fclose(fp);
	pthread_mutex_unlock(&mu_deviceStats);
	return true;
}

static bool writeStats()
{
	pthread_mutex_lock(&mu_statsFile);
	FILE* fp = fopen(statsFile, "w+");
	char buf[256], currentInterface[16];
	int devices = 0, ips = 0, devicesRead = 0;
	
	pthread_mutex_unlock(&mu_statsFile);
	
	syslog (LOG_NOTICE, "Server: Attempting to write statistics to file");
	
	if (!fp) {
		syslog (LOG_CRIT, "Server: Unable to open statistics file");
		return false;
	}
	
	pthread_mutex_lock(&mu_deviceStats);
	fprintf(fp, "#stat_head_begin\n");
	fprintf(fp, "#device_count=%d\n", deviceCount);
	for (int i = 0; i < deviceCount; i++)
	fprintf(fp, " %s:%d\n", deviceStats[i].deviceName, deviceStats[i].ipCount);
	fprintf(fp, "#stat_head_end\n");
	
	for (int i = 0; i < deviceCount; i++) {
		fprintf(fp, "%s\n", deviceStats[i].deviceName);
		for (struct ipStat_t* entry = (struct ipStat_t*) avlFirst(deviceStats[i].ipTree); entry; entry = (struct ipStat_t*) avlNext(deviceStats[i].ipTree))
			fprintf(fp, " %" PRIu32 ":%d\n", entry->ip, entry->packetCount);
	}
	pthread_mutex_unlock(&mu_deviceStats);
	fflush(fp);
	fclose(fp);
	syslog (LOG_NOTICE, "Server: Written statistics data to file");
}

/*Sniffer thread*/
void sniffPackets(char * iface)
{
	static bool isFirstRun = true;
	bool userDeviceFound = false;
	int devicesFound = 0;
	pcap_if_t *alldevsp;
	pcap_t *handle;
	char errbuf[100] , devNames[100][100];
        
	//Pcap init
	if(pcap_findalldevs( &alldevsp , errbuf))
	{
		syslog (LOG_CRIT, "Server: Unable to find any devices");
		write(initPipe[1], "ERR_NODEVICES", sizeof("ERR_NODEVICES") + 1);
		return;
	}
        
	pthread_mutex_lock(&mu_deviceStats);
	selDeviceIndex = 0;
	pthread_mutex_unlock(&mu_deviceStats);

	write(initPipe[1], "NOT_DEVINIT_SUCCESS", sizeof("NOT_DEVINIT_SUCCESS") + 1);
	
	for(pcap_if_t* device = alldevsp ; device != NULL ; device = device->next)
	{
		if(device->name != NULL)
			strcpy(devNames[devicesFound] , device->name);
		
		if (strcmp(devNames[devicesFound], iface) == 0) {
			
			pthread_mutex_lock(&mu_deviceStats);
			selDeviceIndex = devicesFound;
			pthread_mutex_unlock(&mu_deviceStats);
			write(initPipe[1], "NOT_USERDEV_FOUND", sizeof("NOT_USERDEV_FOUND") + 1);
			userDeviceFound = true;
		}
		devicesFound++;
	}
	
	if (!userDeviceFound)
		write(initPipe[1], "NOT_USERDEV_NOTFOUND", sizeof("NOT_USERDEV_NOTFOUND") + 1);
	
	//Cleanup before reading from file
	pthread_mutex_lock(&mu_deviceStats);	
	if (!isFirstRun) {	
		for (int i = 0; i < deviceCount; i++) {
			avlCloseWithFunction(deviceStats[i].ipTree, freeNodeData);
		}
		free(deviceStats);
	}
	else
		isFirstRun = false;
		
	deviceCount = devicesFound;
	pthread_mutex_unlock(&mu_deviceStats);
	
	//Internal structure init	
	if (readStats()) {
		//Continue allocating but for new ifaces
		int newDevices = devicesFound;
		int *newDevicesMask = (int*) malloc(sizeof(int) * devicesFound);
		
		//Count how many *new* devices were found and set mask to filter out existing during init
		for (int i = 0; i < devicesFound; i++) {
			pthread_mutex_lock(&mu_deviceStats);
			for (int j = 0; j < deviceCount; j++) {
				if (strcmp(devNames[i], deviceStats[j].deviceName) == 0) {
					newDevices--;
					newDevicesMask[i] = 1;
					break;
				}
				else
					newDevicesMask[i] = 0;
			}
			pthread_mutex_unlock(&mu_deviceStats);
		}
		
		pthread_mutex_lock(&mu_deviceStats);
		deviceStats = (struct deviceStat_t*) realloc(deviceStats, sizeof(struct deviceStat_t) * (deviceCount + newDevices));	
		
		//Init new devices
		for (int i = deviceCount; i < deviceCount + newDevices; i++) {
			for (int j = 0; j < devicesFound; j++) {
				if (newDevicesMask[j] == 0) {
					newDevicesMask[j] = 1;
					strcpy(deviceStats[i].deviceName, devNames[j]);
				}
			}
			deviceStats[i].ipCount = 0;
			deviceStats[i].ipTree = avlNewTree(cmp_ipStat, 0, sizeof(in_addr_t));
		}
		
		deviceCount += newDevices;
		pthread_mutex_unlock(&mu_deviceStats);
		
		free (newDevicesMask);
	}
	else {
		pthread_mutex_lock(&mu_deviceStats);
		deviceStats = (struct deviceStat_t*) malloc(sizeof(struct deviceStat_t) * deviceCount);
		for (int i = 0; i < deviceCount; i++) {
			strcpy(deviceStats[i].deviceName, devNames[i]);
			deviceStats[i].ipCount = 0;                       
			deviceStats[i].ipTree = avlNewTree(cmp_ipStat, 0, sizeof(in_addr_t)); 
		}
		pthread_mutex_unlock(&mu_deviceStats);		
	}		
	
	//Open handle
	handle = pcap_open_live(devNames[selDeviceIndex] , 65536 , 1 , 200 , errbuf);
	if (handle == NULL) {
		syslog (LOG_WARNING, "Server: Couldn't open device for sniffing");
		write(initPipe[1], "ERR_HANDLE_FAIL", sizeof("ERR_HANDLE_FAIL") + 1);
		return;
	}
	if (pcap_datalink(handle) != 1) {
		syslog (LOG_WARNING, "Server: Incorrect datalink type");
		write(initPipe[1], "ERR_INVDATALINK", sizeof("ERR_INVDATALINK") + 1);
		return;            
	}
            	
	//Signal command thread that everything's OK
	write(initPipe[1], "NOT_HANDLE_SUCCESS", sizeof("NOT_HANDLE_SUCCESS") + 1);

	pthread_mutex_lock(&mu_isSniffing);
	sniffingFlag = true;
	pthread_mutex_unlock(&mu_isSniffing);
	
	//Sniffer loop
	while (isSniffing()) {
		struct pcap_pkthdr *header;
		const u_char *pkt_data;
		
		int pktRes = pcap_next_ex(handle, &header, &pkt_data);
		
		if(pktRes == 0) //Timed out
			continue;
		
		struct ethhdr *eth = (struct ethhdr*) pkt_data;
		if (eth->h_proto != htons(ETH_P_IP))
			continue;
                
		struct iphdr *iph = (struct iphdr *)(pkt_data  + sizeof(struct ethhdr));
 
		pthread_mutex_lock(&mu_deviceStats);
		        
		struct ipStat_t* foundNode = (struct ipStat_t*) avlFind(deviceStats[selDeviceIndex].ipTree, (DSKEY) iph->saddr);		
		
		if (foundNode)
			foundNode->packetCount++;
		else {
			struct ipStat_t* ipEntry = calloc(1, sizeof(struct ipStat_t));
			ipEntry->ip = iph->saddr;
			ipEntry->packetCount = 1;
                        
			avlAdd(deviceStats[selDeviceIndex].ipTree, ipEntry->ip, (void*) ipEntry);
			
			deviceStats[selDeviceIndex].ipCount++;
		}
		pthread_mutex_unlock(&mu_deviceStats);
	}
	
	pcap_close(handle);
	writeStats();
}

/*Handle commands thread*/
void processRequests()
{
	char *socket_path = "\0hidden";
	struct sockaddr_un addr;
	bool startFlag = false;
	char buf[256], currentIface[32] = "eth0";
	int fd, cl, rc;
	pthread_t snifferThread;

	//Pipe init
	if (pipe(initPipe) < 0) {
		syslog (LOG_ERR, "Server: Error creating pipe between threads");
	} 
	
	//Sockets init
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		syslog (LOG_CRIT, "Server: Unable to create socket");
		exit(-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (*socket_path == '\0') {
		*addr.sun_path = '\0';
		strncpy(addr.sun_path + 1, socket_path + 1, sizeof(addr.sun_path) - 2);
	} 
	else {
		strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
		unlink(socket_path);
	}

	if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		syslog (LOG_CRIT, "Server: Unable to bind socket");
		exit(-1);
	}

	if (listen(fd, 5) == -1) {
		syslog (LOG_CRIT, "Server: Unable to listen port");
		exit(-1);
	}	
	
	while (!isShutdown()) {
		buf[0] = 0;
		if ((cl = accept(fd, NULL, NULL)) != -1) { //Handle commands
			
			rc = read(cl, buf, sizeof(buf));
			
			if (rc > 0) {
				char * tokP = strtok(buf, ";");
				switch (atoi(tokP))
				{
					case 0:
						if (startFlag) {
							if (!writeWrap(cl, "Sniffer already running! Use 'stop' to stop it\n", sizeof("Sniffer already running! Use 'stop' to stop it\n")))
								syslog (LOG_WARNING, "Server: Partial write to socket");
							syslog (LOG_WARNING, "Server: Request - Sniffer already started");							
						}
						else {	
							//Start sniffer thread
							char pipeBuf[32];
                                                
							pthread_create(&snifferThread, NULL, (void*) &sniffPackets, &currentIface);
                                                        
							read(initPipe[0], pipeBuf, sizeof(pipeBuf));
                                                        
							if (strcmp(pipeBuf, "NOT_DEVINIT_SUCCESS") == 0) {
                                                            
								read(initPipe[0], pipeBuf, sizeof(pipeBuf)); //Skip device list init signal
								read(initPipe[0], pipeBuf, sizeof(pipeBuf)); //Listen for handle init
								
								if (strcmp(pipeBuf, "ERR_HANDLE_FAIL") == 0) {	
									startFlag = false;								
									pthread_join(snifferThread, NULL);
									
									if (!writeWrap(cl, "Couldn't start sniffer: unable to open device\n", sizeof("Couldn't start sniffer: unable to open device\n")))
										syslog (LOG_WARNING, "Server: Partial write to socket");							
									syslog (LOG_WARNING, "Server: Couldn't open device for sniffing");								
								}
								else if (strcmp(pipeBuf, "ERR_INVDATALINK") == 0) {
									startFlag = false;								
									pthread_join(snifferThread, NULL);
									
									if (!writeWrap(cl, "Couldn't start sniffer: non-ethernet device selected\n", sizeof("Couldn't start sniffer: non-ethernet device selected\n")))
										syslog (LOG_WARNING, "Server: Partial write to socket");							
									syslog (LOG_WARNING, "Server: Incorrect device datalink type, aborting sniffing");                                                                    
                                                                }
								else {
									startFlag = true;
									
									if (!writeWrap(cl, "Sniffer started!\n", sizeof("Sniffer started!\n")))
										syslog (LOG_WARNING, "Server: Partial write to socket");							
									syslog (LOG_NOTICE, "Server: Sniffer started by user request");
								}								
							}
							else {
								startFlag = false;								
								pthread_join(snifferThread, NULL);
								
								if (!writeWrap(cl, "Couldn't start sniffer: no devices found\n", sizeof("Couldn't start sniffer: no devices found\n")))
									syslog (LOG_WARNING, "Server: Partial write to socket");							
								syslog (LOG_WARNING, "Server: No devices found for sniffing");									
							}
							
						}
						break;
					case 1:
						if (!startFlag) {
							if (!writeWrap(cl, "Sniffer already stopped! Use 'start' to start it up\n", sizeof("Sniffer already stopped! Use 'start' to start it up\n")))
								syslog (LOG_WARNING, "Server: Partial write to socket");								
							syslog (LOG_WARNING, "Server: Request - Sniffer already stopped");							
						}
						else {
							startFlag = false;
							
							pthread_mutex_lock(&mu_isSniffing);
							sniffingFlag = false;
							pthread_mutex_unlock(&mu_isSniffing);
							
							pthread_join(snifferThread, NULL);
							
							if (!writeWrap(cl, "Sniffer stopped!\n", sizeof("Sniffer stopped!\n")))
								syslog (LOG_WARNING, "Server: Partial write to socket");							
							syslog (LOG_NOTICE, "Server: Sniffer stopped by user request");
						}
						break;
					case 2:
						tokP = strtok(NULL, ";");
						if (tokP != NULL) {
							int ifaceIndex = -1;
							
							pthread_mutex_lock(&mu_deviceStats);
							for (int i = 0; i < deviceCount; i++)
								if (strcmp(deviceStats[i].deviceName, tokP) == 0)
									ifaceIndex = i;
							pthread_mutex_unlock(&mu_deviceStats);
							
							sendStatsOnIface(cl, ifaceIndex);
						}	
						else
							sendStats(cl);
						syslog (LOG_NOTICE, "Server: Query - sent interface stats to client");
						break;
					case 3:
						tokP = strtok(NULL, ";");						
						sendIpStats(tokP, cl);
						syslog (LOG_NOTICE, "Server: Query - sent IP stats to client");
						break;
					case 4:
						tokP = strtok(NULL, ";");
						char * iface = tokP;
						strcpy(currentIface, iface);
						
						//Restart thread with new interface if is running
						if (startFlag) {
							bool ifaceFound = true;
							char pipeBuf[32];
							
							pthread_mutex_lock(&mu_isSniffing);
							sniffingFlag = false;
							pthread_mutex_unlock(&mu_isSniffing);
							
							pthread_join(snifferThread, NULL);
                                                                                                         							
							pthread_create(&snifferThread, NULL, (void*) &sniffPackets, &currentIface);
                                                        
							read(initPipe[0], pipeBuf, sizeof(pipeBuf));
 							
							if (strcmp(pipeBuf, "NOT_DEVINIT_SUCCESS") == 0) {
								read(initPipe[0], pipeBuf, sizeof(pipeBuf));   
								//Sniffer thread passed device init
								if (strcmp(pipeBuf, "NOT_USERDEV_FOUND") == 0)
									ifaceFound = false;
								
								read(initPipe[0], pipeBuf, sizeof(pipeBuf));  
								//Sniffer thread passed handle init
								if (strcmp(pipeBuf, "ERR_HANDLE_FAIL") == 0) {	
									//Handle didn't init properly
									startFlag = false;									
									pthread_join(snifferThread, NULL);
									
									if (!writeWrap(cl, "Couldn't start sniffer: unable to open device\n", sizeof("Couldn't start sniffer: unable to open device\n")))
										syslog (LOG_WARNING, "Server: Partial write to socket");							
									syslog (LOG_WARNING, "Server: Couldn't open device for sniffing");
								}
								else if (strcmp(pipeBuf, "ERR_INVDATALINK") == 0) {
									startFlag = false;								
									pthread_join(snifferThread, NULL);
									
									if (!writeWrap(cl, "Couldn't start sniffer: non-ethernet device selected\n", sizeof("Couldn't start sniffer: non-ethernet device selected\n")))
										syslog (LOG_WARNING, "Server: Partial write to socket");							
									syslog (LOG_WARNING, "Server: Incorrect device datalink type, aborting sniffing");                                                                       
                                }
								else {
									if (ifaceFound) {
										if (!writeWrap(cl, "Interface set for sniffing\n", sizeof("Interface set for sniffing\n")))
											syslog (LOG_WARNING, "Server: Partial write to socket");
										syslog (LOG_NOTICE, "Server: Selected new interface by user request");
									}									
									else {
										if (!writeWrap(cl, "Interface not found! Resuming sniffing on default interface\n", sizeof("Interface not found! Resuming sniffing on default interface\n")))
											syslog (LOG_WARNING, "Server: Partial write to socket");
										syslog (LOG_NOTICE, "Server: Requested interface not found, selected default");
									} 									
								}								
							}
							else {
								//No devices found
								startFlag = false;								
								pthread_join(snifferThread, NULL);
								
								if (!writeWrap(cl, "Couldn't start sniffer: no devices found\n", sizeof("Couldn't start sniffer: no devices found\n")))
									syslog (LOG_WARNING, "Server: Partial write to socket");							
								syslog (LOG_WARNING, "Server: No devices found for sniffing");										
							}
						}
						else {
							if (!writeWrap(cl, "Interface set for sniffing\n", sizeof("Interface set for sniffing\n")))
									syslog (LOG_WARNING, "Server: Partial write to socket");
							syslog (LOG_NOTICE, "Server: Selected new interface by user request");                                    
						}

						syslog (LOG_NOTICE, "Server: Selected new interface for sniffer");
						break;
					default:
						syslog (LOG_WARNING, "Server: Received unknown operation index");
				}
			}
			else if (rc == -1)
				syslog (LOG_ERR, "Server: Error reading data from socket");
			else
				syslog (LOG_NOTICE, "Server: Received empty request, ignoring");
			close(cl);
		}
	}
	//Thread termination routines
	close (fd);
	if (startFlag) {
		
		pthread_mutex_lock(&mu_isSniffing);
		sniffingFlag = false;
		pthread_mutex_unlock(&mu_isSniffing);
		
		pthread_join(snifferThread, NULL);		
	}
}

int main() {          
	daemonize();
	pthread_create(&handleRequestsThread, NULL, (void*) &processRequests, NULL);
	pthread_exit(0);
}
