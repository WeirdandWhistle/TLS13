#include "main.h"

int start_socket(int port, int backlog){
    int soc = socket(AF_INET, SOCK_STREAM, 0);

	int opt = 1;
	setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	
	struct sockaddr_in my_addr;
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(port);
	my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	int binded = bind(soc, (struct sockaddr *)&my_addr, sizeof(my_addr));
	if(binded<0){
        printf("bind error!");
        return -1;
    }

	listen(soc, backlog);
    return soc;
}
int accept_socket(int socket){
    struct sockaddr accept_addr;
	socklen_t addrlen = sizeof(accept_addr);

	int acc = accept(socket, &accept_addr, &addrlen);
	if(acc<0){
        printf("accept error!");
        return -1;
    }
    return acc;
}