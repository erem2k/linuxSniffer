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

//char *socket_path = "./socket";
char *socket_path = "\0hidden";
const char *statsFile = "./snifferStats.dat";
struct deviceStat_t *deviceStats = NULL;
int deviceCount = 0, selDeviceIndex = 0;

/*Data structures*/
struct ipStat_t {
	in_addr_t  ip;
	int packetCount;
};

struct deviceStat_t {
	char deviceName[16];
	struct ipStat_t * ipStats;
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

void setSocketBlockingEnabled(int fd, bool blocking)
{
   /*Disabled blocking disables main loop from blocking at accept() waiting for signal from socket
     This allows sniffer loop to run */
   if (fd < 0) 
	   return;
   int flags = fcntl(fd, F_GETFL, 0);
   if (flags < 0) 
	   return;
   flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
   fcntl(fd, F_SETFL, flags);
}

static void merge(struct ipStat_t *arr, int low, int mid, int high)
{
    int mergedSize = high - low + 1;
    struct ipStat_t *temp = (struct ipStat_t *)malloc(mergedSize * sizeof(struct ipStat_t));
    int mergePos = 0;
    int leftPos = low;
    int rightPos = mid + 1;

    while (leftPos <= mid && rightPos <= high)     
    {
        if (arr[leftPos].ip < arr[rightPos].ip)
            temp[mergePos++] = arr[leftPos++];
        else
            temp[mergePos++] = arr[rightPos++];
    }

    while (leftPos <= mid)
        temp[mergePos++] = arr[leftPos++];

    while (rightPos <= high)
        temp[mergePos++] = arr[rightPos++];

    for (mergePos = 0; mergePos < mergedSize; ++mergePos)
        arr[low + mergePos] = temp[mergePos];

    free(temp);
}

static void msort_ip(struct ipStat_t *arr, int low, int high)
{
    if (low < high)
    {
        int mid = (low + high) / 2;

        msort_ip(arr, low, mid);
        msort_ip(arr, mid + 1, high);

        merge(arr, low, mid, high);
    }
}

int bsearch_ip(in_addr_t  ip)
{
	int floor = 0, ceiling = deviceStats[selDeviceIndex].ipCount;
	while (floor <= ceiling) {
		int median = (floor + (ceiling - floor) / 2);
		if (deviceStats[selDeviceIndex].ipStats[median].ip == ip) {
			return median;
		}
                if (deviceStats[selDeviceIndex].ipStats[median].ip < ip)
                        floor = median + 1;
                else
                        ceiling = median - 1;
	}
	return -1;
}

/*Server-client communication functions*/

void sendStatsOnIface(int fd, int index)
{
	char *returnString;
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
                        for (int j = 0; j < deviceStats[i].ipCount; j++) {
                                char snum[16];
                                struct in_addr src;
                                src.s_addr = deviceStats[i].ipStats[j].ip;
                                strcat(returnString, inet_ntoa(src));
                                strcat(returnString, " : Packets received ");
                                sprintf(snum, "%d", deviceStats[i].ipStats[j].packetCount);
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
		for (int j = 0; j < deviceStats[index].ipCount; j++) {
			char snum[8];
			strcat(returnString, inet_ntoa((struct in_addr){deviceStats[index].ipStats[j].ip}));
			strcat(returnString, " : Packets received ");
                        sprintf(snum, "%d", deviceStats[index].ipStats[j].packetCount);
			strcat(returnString, snum);
			strcat(returnString, "\n");
		}		
	}
	else {
		returnString = (char*) malloc(sizeof("Interface not found!\n"));
		returnString = "Interface not found!\n";
	}
		
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
	index = bsearch_ip(requestedIp.s_addr);
	
	if (index != -1) {
		char *returnString = (char*) malloc((23 + strlen(ip) + 8) * sizeof(char)); //Text + IP + Packet count
		sprintf (returnString, "IP:%s\nPackets Received:%d\n", ip, deviceStats[selDeviceIndex].ipStats[index].packetCount);
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
	for (int i = 0; i < deviceCount; i++)
		free(deviceStats[i].ipStats);
	free(deviceStats);
	
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

    /* An error occurred */
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

    openlog ("task_sniffer", LOG_PID, LOG_DAEMON);
}

/*File I/O*/
static bool readStats()
{
	//Heavily relies on file structure being correct
	FILE* fp = fopen(statsFile, "r");
	char buf[256];
	int devices = 0, ips = 0, devicesRead = 0;
	
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
                
		deviceStats = (struct deviceStat_t*) malloc(sizeof(struct deviceStat_t) * devices);
		
		for (int i = 0; i < devices; i++) {
			char * tokP;
			fgets(buf, 256, fp);
			buf[strcspn(buf, "\n")] = 0;
			tokP = strtok(buf, " :");
			
			strcpy(deviceStats[i].deviceName, tokP);
			tokP = strtok(NULL, " :");
			deviceStats[i].ipCount = atoi(tokP);
			
			deviceStats[i].ipStats = (struct ipStat_t*) malloc(sizeof(struct ipStat_t) * (deviceStats[i].ipCount / 100 + 1) * 100);
			//100-element pages to avoid reallocating each time new ip is found
		}
		
		fgets(buf, 256, fp);
		buf[strcspn(buf, "\n")] = 0;		
		
		if (strcmp(buf, "#stat_head_end") != 0)
			syslog (LOG_WARNING, "Server: Couldn't find file header closure");
		
		deviceCount = devices;
	}
	
	while (fgets(buf, 256, fp) != NULL) {	//Processes each device's IPs
		buf[strcspn(buf, "\n")] = 0;
		
		for (int i = 0; i < deviceStats[devicesRead].ipCount; i++) {
			char *tokP;
			fgets(buf, 256, fp);
			buf[strcspn(buf, "\n")] = 0;
			tokP = strtok(buf, " :");
			sscanf(tokP, "%"SCNu32, &(deviceStats[devicesRead].ipStats[i].ip));
			tokP = strtok(NULL, " :");
			deviceStats[devicesRead].ipStats[i].packetCount = atoi(tokP);
		}

		devicesRead++;
	}
	syslog (LOG_NOTICE, "Server: Statistics file read complete");
	fclose(fp);
	return true;
}

static bool writeStats()
{
	FILE* fp = fopen(statsFile, "w+");
	char buf[256], currentInterface[16];
	int devices = 0, ips = 0, devicesRead = 0;
	
	syslog (LOG_NOTICE, "Server: Attempting to write statistics to file");
	
	if (!fp) {
		syslog (LOG_CRIT, "Server: Unable to open statistics file");
		return false;
	}
	
	fprintf(fp, "#stat_head_begin\n");
	fprintf(fp, "#device_count=%d\n", deviceCount);
	for (int i = 0; i < deviceCount; i++)
		fprintf(fp, " %s:%d\n", deviceStats[i].deviceName, deviceStats[i].ipCount);
	fprintf(fp, "#stat_head_end\n");
	
	for (int i = 0; i < deviceCount; i++) {
		fprintf(fp, "%s\n", deviceStats[i].deviceName);
		for (int j = 0; j < deviceStats[i].ipCount; j++)
			fprintf(fp, " %" PRIu32 ":%d\n", deviceStats[i].ipStats[j].ip, deviceStats[i].ipStats[j].packetCount);
	}
        fflush(fp);
        fclose(fp);
	syslog (LOG_NOTICE, "Server: Written statistics data to file");
}

int main() {
	struct sockaddr_un addr;
	char buf[256];
	int fd, cl, rc, pktRes, devicesFound = 0;
	bool startFlag = false, isFirstRun = true;
    pcap_if_t *alldevsp , *device;
    pcap_t *handle;
	char errbuf[100] , devNames[100][100];
	
	daemonize();
	
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
	} else {
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
	
	//Pcap init
    if(pcap_findalldevs( &alldevsp , errbuf) )
    {
        syslog (LOG_CRIT, "Server: Unable to find any devices");
        exit(1);
    }
	
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        if(device->name != NULL)
            strcpy(devNames[devicesFound] , device->name);
        devicesFound++;
		if (strcmp(devNames[devicesFound], "eth0") == 0)
			selDeviceIndex = devicesFound;
    }
	
	deviceCount = devicesFound;
	
	//Internal structure init	
	if (readStats()) {
		//Continue allocating but for new ifaces
		int newDevices = devicesFound;
		int *newDevicesMask = (int*) malloc(sizeof(int) * devicesFound);
		
		//Count how many *new* devices were found and set mask to filter out existing during init
		for (int i = 0; i < devicesFound; i++) {
			for (int j = 0; j < deviceCount; j++) {
				if (strcmp(devNames[i], deviceStats[j].deviceName) == 0) {
					newDevices--;
					newDevicesMask[i] = 1;
					break;
				}
				else
					newDevicesMask[i] = 0;
			}
		}

		deviceStats = (struct deviceStat_t*) realloc(deviceStats, sizeof(struct deviceStat_t) * (deviceCount + newDevices));	
		
		//Init new devices
		for (int i = deviceCount; i < deviceCount + newDevices; i++) {
			for (int j = 0; j < devicesFound; j++) {
				if (newDevicesMask[j] == 0) {
					newDevicesMask[j] = 1;
					strcpy(deviceStats[i].deviceName, devNames[j]);
				}
			}
			deviceStats[i].ipStats = (struct ipStat_t*) malloc(sizeof(struct ipStat_t) * 100);
                        deviceStats[i].ipCount = 0;
		}		
		
		deviceCount += newDevices;
		free (newDevicesMask);
	}
	else {
		deviceStats = (struct deviceStat_t*) malloc(sizeof(struct deviceStat_t) * deviceCount);
		for (int i = 0; i < deviceCount; i++) {
			strcpy(deviceStats[i].deviceName, devNames[i]);
			deviceStats[i].ipStats = (struct ipStat_t*) malloc(sizeof(struct ipStat_t) * 100);
                        deviceStats[i].ipCount = 0;
		}		
	}
	//Main Loop
	while (true) {
            buf[0] = 0;
		if ((cl = accept(fd, NULL, NULL)) != -1) { //Handle commands
			rc = read(cl, buf, sizeof(buf));
			//Assume data sent is in valid format
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
							if (!isFirstRun) {
								for (int i = 0; i < deviceCount; i++)
									free(deviceStats[i].ipStats);
								free(deviceStats);
								readStats();								
							}
							else
								isFirstRun = false;

							handle = pcap_open_live(devNames[selDeviceIndex] , 65536 , 1 , 200 , errbuf);
							
							if (handle == NULL) {
								startFlag = false;
                                                                setSocketBlockingEnabled(fd, true);
								if (!writeWrap(cl, "Couldn't start sniffer: unable to open device\n", sizeof("Couldn't start sniffer: unable to open device\n")))
									syslog (LOG_WARNING, "Server: Partial write to socket");							
								syslog (LOG_WARNING, "Server: Couldn't open device for sniffing");								
							}
							else {
                                                                setSocketBlockingEnabled(fd, false);
                                                                startFlag = true;								
                                                                if (!writeWrap(cl, "Sniffer started!\n", sizeof("Sniffer started!\n")))
									syslog (LOG_WARNING, "Server: Partial write to socket");							
								syslog (LOG_NOTICE, "Server: Sniffer started by user request");
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
                                                        setSocketBlockingEnabled(fd, true);	
                                                        startFlag = false;
							pcap_close(handle);
							
							writeStats();
							selDeviceIndex = 0;
							deviceCount = 0;
							
							if (!writeWrap(cl, "Sniffer stopped!\n", sizeof("Sniffer stopped!\n")))
								syslog (LOG_WARNING, "Server: Partial write to socket");							
							syslog (LOG_NOTICE, "Server: Sniffer stopped by user request");
						}
						break;
					case 2:
						tokP = strtok(NULL, ";");
						if (tokP != NULL) {
                                                    int ifaceIndex = -1;
                                                    for (int i = 0; i < deviceCount; i++)
                                                        if (strcmp(deviceStats[i].deviceName, tokP) == 0)
                                                            ifaceIndex = i;
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
                                                int ifaceIndex = -1;
						
						for (int i = 0; i < deviceCount; i++) {
							if (strcmp(devNames[i], iface) == 0)
								ifaceIndex = i;
						}
                                                
                                                if (ifaceIndex != -1) {
                                                    if (startFlag)
                                                        pcap_close(handle);
							
                                                    handle = pcap_open_live(devNames[ifaceIndex] , 65536 , 1 , 200 , errbuf);

                                                    if (handle == NULL) {
                                                            startFlag = false;
                                                            setSocketBlockingEnabled(fd, true);
                                                            if (!writeWrap(cl, "Couldn't change interface: unable to open device\n", sizeof("Couldn't change interface: unable to open device\n")))
                                                                    syslog (LOG_WARNING, "Server: Partial write to socket");							
                                                            syslog (LOG_WARNING, "Server: Couldn't open new device for sniffing");								
                                                    }
                                                    else {
                                                            setSocketBlockingEnabled(fd, false);
                                                            startFlag = true;
                                                            selDeviceIndex = ifaceIndex;
                                                            if (!writeWrap(cl, "Interface set for sniffing\n", sizeof("Interface set for sniffing\n")))
                                                                    syslog (LOG_WARNING, "Server: Partial write to socket");							
                                                            syslog (LOG_NOTICE, "Server: Selected new interface by user request");
                                                    }                                                    
                                                }
                                                else
                                                    if (!writeWrap(cl, "Interface not found\n", sizeof("Interface not found\n")))
                                                           syslog (LOG_WARNING, "Server: Partial write to socket");                                                   
						
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
		if (startFlag) {	//Sniff single packet
			struct pcap_pkthdr *header;
			const u_char *pkt_data;
			int index = 0;
                        bool isReadable = false;
			
			pktRes = pcap_next_ex(handle, &header, &pkt_data);
			
			if(pktRes == 0) //Timed out
				continue;
			
			struct iphdr *iph = (struct iphdr *)(pkt_data  + sizeof(struct ethhdr));
                        
                        switch (iph->protocol) 
                        {
                            case 1:  //ICMP Protocol
                            case 6:  //TCP Protocol
                            case 17: //UDP Protocol
                                isReadable = true;
                                break;
                            default: //Other protocols
                                break;
                        }                        
                        
                        if (!isReadable)
                            continue;
                        
			index = bsearch_ip(iph->saddr);
			if (index != -1)
				deviceStats[selDeviceIndex].ipStats[index].packetCount++;
			else {
				//Realloc for additional 100 IPs if page is exceeded
				if ((deviceStats[selDeviceIndex].ipCount % 100) == 0 && deviceStats[selDeviceIndex].ipCount != 0) {
					deviceStats[selDeviceIndex].ipStats = (struct ipStat_t*) 
						realloc(deviceStats[selDeviceIndex].ipStats, (sizeof(struct ipStat_t) * (deviceStats[selDeviceIndex].ipCount / 100 + 1)));					
				}
				deviceStats[selDeviceIndex].ipStats[deviceStats[selDeviceIndex].ipCount].ip = iph->saddr;
				deviceStats[selDeviceIndex].ipStats[deviceStats[selDeviceIndex].ipCount].packetCount = 1;
                                deviceStats[selDeviceIndex].ipCount++;
				
				/*Reason for sorting here, of all places, is because task requires IP lookup to have complexity of O(log(n))
				  Lookup itself is based on binary search, hence O(log(n)) complexity, but it requires array to be sorted beforehand
				  This leaves us with two options - sort every N packets and risk missing the lookup call or sort on every insert*/
				msort_ip(deviceStats[selDeviceIndex].ipStats, 0, deviceStats[selDeviceIndex].ipCount - 1);
			}
		}
		sleep(1);
	}
	
	daemonShutdown();
	
	return 0;
}