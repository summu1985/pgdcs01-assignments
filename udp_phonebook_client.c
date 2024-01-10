/***************************************************************** 
 * A sample implementation of a UDP phonebook client application.
 * This application expects the phonebook server application
 * host address and message to send to the server as command line
 * arguments.
 * The client then combines these parameters in a parsable string
 * using : as delimiter and sends to the server over an UDP socket
 * The server response is recieved in the UDP payload in string
 * format and is displayed on the screen for user consumption
 ******************************************************************/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define FILENAME "help.txt"

/****************************************************
 * This function is a helper function, responsible 
 * for printing out the help message that is the
 * content of the help.txt file, that should be 
 * present in the same directory
 ****************************************************/

void print_usage() {
    FILE *fptr; 
  
    char filename[100], c; 
  
    // Open file 
    fptr = fopen(FILENAME, "r"); 
    if (fptr == NULL) 
    { 
        printf("Cannot open file \n"); 
        exit(0); 
    } 
  
    // Read contents from file 
    c = fgetc(fptr); 
    while (c != EOF) 
    { 
        printf ("%c", c); 
        c = fgetc(fptr); 
    } 
  
    fclose(fptr); 
}

int main(int argc, char *argv[]){
    int socket_desc;
    struct sockaddr_in server_addr;
    char server_message[2000], client_message[2000];
    int server_struct_length = sizeof(server_addr);
    
    // Clean buffers:
    memset(server_message, '\0', sizeof(server_message));
    memset(client_message, '\0', sizeof(client_message));
   
	// If number of arguments in less than 2, then incorrect
	// number of parameters has been passed. So help the user
	// by displaying the usage information
	if (argc < 3) {
		print_usage();
        exit(1);
    } 
 
    // Create socket:
    // We are simulating a UDP client, so we create a UDP
    // socket
    socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    if(socket_desc < 0){
        fprintf(stderr,"Error while creating socket\n");
        return -1;
    }
    
    // Set port and IP:
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(2000);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    // Get input from the user:
    // Send the arguments 2 and 3, if present, to server as UDP payload
    strncpy(client_message, argv[2], strlen(argv[2]));
	if (argc == 4) {
		strncpy(client_message+strlen(argv[2]),":", 1);
    	strncpy(client_message+strlen(argv[2])+1, argv[3], strlen(argv[3]));
	}
    
    // Send the message to server:
    if(sendto(socket_desc, client_message, strlen(client_message), 0,
         (struct sockaddr*)&server_addr, server_struct_length) < 0){
        fprintf(stderr,"Unable to send message\n");
        return -1;
    }
    
    // Receive the server's response:
    if(recvfrom(socket_desc, server_message, sizeof(server_message), 0,
         (struct sockaddr*)&server_addr, &server_struct_length) < 0){
        fprintf(stderr,"Error while receiving server's msg\n");
        return -1;
    }
    
    fprintf(stdout,"%s\n", server_message);
    
    // Close the socket:
    close(socket_desc);
    
    return 0;
}
