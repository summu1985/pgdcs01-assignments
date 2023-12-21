#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <malloc.h>

int get_command_index(const char *input_string) {
	const char *commands[] = {"PING", "LOOKUP","ADD", "REMOVE"};
	int command_table_size = sizeof(commands)/sizeof(char *);
	int i, index = -1;

	for (i=0 ; i<command_table_size ; i++) {
		if(!strncmp(commands[i], input_string, strlen(commands[i]))) {
			index = i;
			break;	
		}
	}

	return index;
}

struct user_entry {
	char username[100];
	char phone_number[15];
	char email[100];
};

// Define a in-memory database of users in the phonebook
#define MAX_USER_ENTRY 50
struct user_entry users[MAX_USER_ENTRY];
int current_user_count = 0;

struct user_entry *lookup_user(const char *input_user) {
	int i;
	struct user_entry *user = NULL;

	for(i=0 ; i<current_user_count ; i++) {
		printf("lookup: username: %s, input username: %s,\n",users[i].username, input_user);
		if (!strncmp(users[i].username, input_user, strlen(users[i].username))) {
			user = malloc(sizeof(struct user_entry));
			strncpy(user->username, users[i].username, strlen(users[i].username));
			printf("phone : %s\n", users[i].phone_number);
			strncpy(user->phone_number, users[i].phone_number, strlen(users[i].phone_number));
			printf("phonenum : %s\n",user->phone_number);
			strncpy(user->email, users[i].email, strlen(users[i].email));
			break;
		}
	}

	return user;
}

int add_user(const struct user_entry *user) {
	int status = -1;
	if (current_user_count > MAX_USER_ENTRY) {
		return status;
	} else {
		strncpy(users[current_user_count].username, user->username, strlen(user->username));
		strncpy(users[current_user_count].phone_number, user->phone_number, strlen(user->phone_number));
			printf("phonenum : %s\n",user->phone_number);
		strncpy(users[current_user_count].email, user->email, strlen(user->email));
			printf("email : %s\n", user->email);
		current_user_count++;
		status = 0;
	}
	return status;
}

int main(void) {
	int socket_desc;
	struct sockaddr_in server_addr, client_addr;
	char server_message[2000], client_message[2000];
	int client_struct_length = sizeof(client_addr);

	// Clean buffers:
	memset(server_message, '\0', sizeof(server_message));
	memset(client_message, '\0', sizeof(client_message));

	//Create UDP socket
	socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    if(socket_desc < 0){
        printf("Error while creating socket\n");
        return -1;
    }
    printf("Socket created successfully\n");
    
    // Set port and IP:
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(2000);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    // Bind to the set port and IP:
    if(bind(socket_desc, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        printf("Couldn't bind to the port\n");
        return -1;
    }
    printf("Done with binding\n");
    
    printf("Listening for incoming messages...\n\n");
    

	for(;;) {
		char *command;
		char *token;
		char *parameter;
		struct user_entry *user = NULL;
    	// Receive client's message:
    	if (recvfrom(socket_desc, client_message, sizeof(client_message), 0,
        	(struct sockaddr*)&client_addr, &client_struct_length) < 0){
        		printf("Couldn't receive\n");
        		return -1;
    	}
    	printf("Received message from IP: %s and port: %i\n",
       		inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
   
   		printf("Msg from client: %s\n", client_message);

		int command_index = get_command_index(client_message);   

			// Respond to client:
			switch(command_index) {
				case 0:
					strcpy(server_message, "PONG");
					break;
				case 1:
					// Lookup case - In this case, a parameter to the command is expected
					// This parameter is the name to lookup. If the name exists in local
					// database, then return the details to client as response
					// Other send "User not found"
					// First validate that the client has supplied the required parameters

					command = strtok(client_message,":");

					if (command == NULL) {
						strcpy(server_message, "Error in command syntax.");
						break;
					} else {
						parameter = strtok(NULL,":");
						if (parameter == NULL) {
							strcpy(server_message, "Error in command syntax.");
							break;
						}
					}
					struct user_entry *user = lookup_user(parameter);
					if (user != NULL) {
						sprintf(server_message,
							"Name:%s#Phone:%s#Email:%s",
							user->username, user->phone_number, user->email
						);
					} else {
						strcpy(server_message, "User not found!");
					}
					break;
				case 2:
					// Add user case - In this case, parameters are expected (username, phone_number, email)
					// after the command. First the validated to be present in the message. Then the information
					// is added in the users array
					token = strtok(client_message,":");
					user = malloc(sizeof(struct user_entry));
					if (token == NULL) {
						strcpy(server_message, "Error in command syntax.");
						break;
					} else {
						command = token;
						printf("token = %s\n", command);
						parameter = strtok(NULL,":");
						if (parameter == NULL) {
							strcpy(server_message, "Error in command syntax.");
							break;
						}
						printf("token = %s\n", parameter);
						strncpy(user->username, parameter, strlen(parameter));
						parameter = strtok(NULL,":");
						if (parameter == NULL) {
							strcpy(server_message, "Error in command syntax.");
							break;
						}
						printf("token = %s\n", parameter);
						strncpy( user->email, parameter, strlen(parameter));
						parameter = strtok(NULL,":");
						if (parameter == NULL) {
							strcpy(server_message, "Error in command syntax.");
							break;
						}
						printf("token = %s\n", parameter);
						strncpy(user->phone_number, parameter,  strlen(parameter));

					}
					if (!add_user(user)){
						strcpy(server_message, "User added");
					} else {
						strcpy(server_message, "User could not be added");
					}
					break;
				case 3:
					strcpy(server_message, "REMOVE");
					break;
				default:
    				strcpy(server_message, "Unknown Command");
					break;
			}
    
    	if (sendto(socket_desc, server_message, strlen(server_message), 0,
        	 (struct sockaddr*)&client_addr, client_struct_length) < 0){
        	printf("Can't send\n");
        	return -1;
    	}

		memset(client_message, '\0', sizeof(client_message));
	}
    
    // Close the socket:
    printf("Closing connection from IP: %s and port: %i\n",
		inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    close(socket_desc);
    
    return 0;
}
