#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>


#define MSG_INCORRECT_COMMAND "Unrecognized syntax. Use CLIENTNAME --h to list available commands"

//char *socket_path = "./socket";
char *socket_path = "\0hidden";

bool writeWrap(int fd, const char* data, size_t dataSize)
{
	int bytesWritten = write(fd, data, dataSize);
	if (bytesWritten != dataSize) {
		if (bytesWritten > 0) 
			return false;
		else {
			perror("Client: Socket write error");
			exit(-1);
		}
	}
	return true;
}

int main(int argc, char *argv[]) {
	//Display results
	struct sockaddr_un addr;
	char buf[256];
	int fd;
	bool outputFlag = false;
        
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("Client: Socket creation error");
		exit(-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (*socket_path == '\0') {
		*addr.sun_path = '\0';
		strncpy(addr.sun_path+1, socket_path+1, sizeof(addr.sun_path)-2);
	} 
	else {
		strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
	}

	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("Client: Connect error");
		exit(-1);
	}
	
	//Handle input, write to socket
	switch (argc)
	{
		case 2:
			if (strcmp(argv[1], "start") == 0) {
				char cmd[] = ";0";
				if (!writeWrap(fd, cmd, sizeof(cmd)))
					fprintf(stderr,"Client: Partial write to socket");
				outputFlag = true;
				break;
			}
			if (strcmp(argv[1], "stop") == 0) {
				char cmd[] = ";1";
				if (!writeWrap(fd, cmd, sizeof(cmd)))
					fprintf(stderr,"Client: Partial write to socket");
				outputFlag = true;
				break;
			}
			if (strcmp(argv[1], "stat") == 0) {
				char cmd[] = ";2";
				if (!writeWrap(fd, cmd, sizeof(cmd)))
					fprintf(stderr,"Client: Partial write to socket");	
				outputFlag = true;
				break;
			}
			if (strcmp(argv[1], "--h") == 0) {
				printf("Available commands:\n");
				printf("\tstart - Start sniffing packets from default or selected interface\n");
				printf("\tstop - Stop sniffing packets");
				printf("\tshow [ip] count - Print received packet count from [ip] address\n");
				printf("\tselect iface [iface] - Set interface for sniffing\n");
				printf("\tstat [iface] - Print all collected statistics for [iface]. If [iface] is omitted, stats for all interfaces are displayed\n");
				printf("\t--h - Show this menu\n");
				break;
			}
			else {
				printf (MSG_INCORRECT_COMMAND);
				break;
			}
		case 3:
			if (strcmp(argv[1], "stat") == 0) {
				char cmdindex[] = ";2;";
				char* cmd = calloc(strlen(cmdindex) + strlen(argv[2]) + 1, sizeof(char));
	
				strcpy(cmd, cmdindex);
				strcat(cmd, argv[2]);
				
				if (!writeWrap(fd, cmd, strlen(cmd) + 1))
					fprintf(stderr, "Client: Partial write to socket");
				outputFlag = true;
				free (cmd);
			}
			else {
				printf (MSG_INCORRECT_COMMAND);
			}
			break;
		case 4:
			if (strcmp(argv[1], "show") == 0 && strcmp(argv[3], "count") == 0) {
                                in_addr_t ipValidator = inet_addr(argv[2]);
                                
                                if (ipValidator != -1) {
                                    char cmdindex[] = ";3;";
                                    char* cmd = calloc(strlen(cmdindex) + strlen(argv[2]), sizeof(char));	
                                    strcpy(cmd, cmdindex);
                                    strcat(cmd, argv[2]);
				
                                    if (!writeWrap(fd, cmd, strlen(cmd) + 1))
                                        fprintf(stderr, "Client: Partial write to socket");
                                    outputFlag = true;
                                    free (cmd);
                                }
                                else
                                    printf("Incorrect IP format!\n");
				break;
			}			
			if (strcmp(argv[1], "select") == 0 && strcmp(argv[2], "iface") == 0) {
				char cmdindex[] = ";4;";
				char* cmd = calloc(strlen(cmdindex) + strlen(argv[3]), sizeof(char));
	
				strcpy(cmd, cmdindex);
				strcat(cmd, argv[3]);
				
				if (!writeWrap(fd, cmd, strlen(cmd) + 1))
					fprintf(stderr, "Client: Partial write to socket");
				outputFlag = true;
				free (cmd);
				break;
			}
			else {
				printf (MSG_INCORRECT_COMMAND);
			}				
		default:
			printf (MSG_INCORRECT_COMMAND);
		
	}
        
	//Handle output
	if (outputFlag) {
		while(read(fd, buf, sizeof(buf)) > 0)
                    printf("%s", buf);
	}

	return 0;
}
