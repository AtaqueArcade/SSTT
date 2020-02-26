#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>

#define TIMEOUT		300
#define REQUIRED_ARGS	2
#define VERSION		24
#define BUFSIZE		8096
#define ERROR		42
#define LOG			44
#define PROHIBIDO	403
#define NOENCONTRADO	404

struct {
	char *ext;
	char *filetype;
} extensions [] = {
	{"gif", "image/gif" },
	{"jpg", "image/jpg" },
	{"jpeg","image/jpeg"},
	{"png", "image/png" },
	{"ico", "image/ico" },
	{"zip", "image/zip" },
	{"gz",  "image/gz"  },
	{"tar", "image/tar" },
	{"htm", "text/html" },
	{"html","text/html" },
	{0,0} };
	
void debug(int log_message_type, char *message, char *additional_info, int socket_fd)
{
	int fd ;
	char logbuffer[BUFSIZE*2];
	
	switch (log_message_type) {
		case ERROR: (void)sprintf(logbuffer,"ERROR: %s:%s Errno=%d exiting pid=%d",message, additional_info, errno,getpid());
			break;
		case PROHIBIDO:
			// Enviar como respuesta 403 Forbidden
			(void)sprintf(logbuffer,"FORBIDDEN: %s:%s",message, additional_info);
			break;
		case NOENCONTRADO:
			// Enviar como respuesta 404 Not Found
			(void)sprintf(logbuffer,"NOT FOUND: %s:%s",message, additional_info);
			break;
		case LOG: (void)sprintf(logbuffer," INFO: %s:%s:%d",message, additional_info, socket_fd); break;
	}

	if((fd = open("webserver.log", O_CREAT| O_WRONLY | O_APPEND,0644)) >= 0) {
		(void)write(fd,logbuffer,strlen(logbuffer));
		(void)write(fd,"\n",1);
		(void)close(fd);
	}
	if(log_message_type == ERROR || log_message_type == NOENCONTRADO || log_message_type == PROHIBIDO) exit(3);
}

int filesize(char *file){
	int fd = open(file+1,O_RDONLY); /* 1 syscall */
	int size = lseek(fd, 0, SEEK_END); /* 2 syscalls */
	return size;
}

char *get_filename_ext(char *filename) {
    char *dot = strrchr(filename, '.');
    if(!dot || dot == filename) return "";
    return dot + 1;
}

void process_web_request(int descriptorFichero)
{
	//Log the petition
	debug(LOG,"request","New HTTP petition has arrived.",descriptorFichero);

	//buf will be the GET buffer, buf2 will contain the file to send
	char buf[BUFSIZE];
	char buf2[BUFSIZE];
	int nbytes = 0;
	 
	// read HTTP petition
	nbytes =read(descriptorFichero, buf, BUFSIZE-1);

	// check for on read errors
	if (nbytes <= 0) {
		close(descriptorFichero);
		char msg[17];
		strcpy(msg, "Read error");
		char info[34];
		strcpy(info, "Buffer read went wrong.");
		debug(ERROR, msg, info, descriptorFichero);
		
		char head[200];
		char d[1000];
		time_t now = time(0);
		struct tm tm = *gmtime(&now);
		strftime(d, sizeof d, "%a, %d %b %Y %H:%M:%S %Z", &tm);
		char response[BUFSIZE];
		sprintf(response, "<head><title>Error page</title><h1>ERROR 400: Bad Request.</br></h1></head><body>Request can't be processed by the server.</body>");
		sprintf(head, "HTTP/1.1 400 Bad Request\r\nDate: %s\r\nContent-Length: %ld\r\ncharset=ISO-8859-1\r\n\r\n", d, (long) strlen(response));
		write(descriptorFichero, head, strlen(head));
		write(descriptorFichero, response, strlen(response));
		close(descriptorFichero);
		debug(ERROR,"400", "Bad Request", descriptorFichero);
	}
	buf[nbytes] = '\0';
	//Petition will be analyzed line by line 
	char *line = strtok(buf, "\r\n");
	
	//variables
	char *op;//http method
	char *pet;//type of petition
	char *dir;//directory
	char *ver;//http version
	char *host;//host
	char *useragent;//useragent
	char *acc;//accept
	char *lang;//accept-languaje
	char *enc;//accept-encoding
	char *ref;//referer
	char *chset;//accept-charset
	char *ka;//keep-alive
	char *con;//conexion
	char *uir;//upgrade insecure requests
	char *ims;//if modified since
	char *date;//date
	char *cc;//cache control
	int fd;//file descriptor to write
	char *ext;//extension
	int cookie = 0;
	
	//Act according to the HTTP method received
	//Check the GET method, deny unsupported methods
	
	op = strsep(&line," ");
	
	pet = op;
	dir = strsep(&line," ");
	ver= strsep(&line," ");
	if (op == NULL || dir == NULL || ver == NULL){
			char head[200];
			char d[1000];
			time_t now = time(0);
			struct tm tm = *gmtime(&now);
			strftime(d, sizeof d, "%a, %d %b %Y %H:%M:%S %Z", &tm);
			char response[BUFSIZE];
			sprintf(response, "<head><title>Error page</title><h1>ERROR 400: Bad Request.</br></h1></head><body>Request can't be processed by the server.</body>");
			sprintf(head, "HTTP/1.1 400 Bad Request\r\nDate: %s\r\nContent-Length: %ld\r\ncharset=ISO-8859-1\r\n\r\n", d, (long) strlen(response));
			write(descriptorFichero, head, strlen(head));
			write(descriptorFichero, response, strlen(response));
			close(descriptorFichero);
			debug(ERROR,"400", "Bad Request", descriptorFichero);
	}else if (strcmp(op, "GET") == 0){
		if ((dir == NULL) || (strcmp(ver, "HTTP/1.1") != 0)){
			char head[200];
			char d[1000];
			time_t now = time(0);
			struct tm tm = *gmtime(&now);
			strftime(d, sizeof d, "%a, %d %b %Y %H:%M:%S %Z", &tm);
			char response[BUFSIZE];
			sprintf(response, "<head><title>Error page</title><h1>ERROR 400: Bad Request.</br></h1></head><body>Request can't be processed by the server.</body>");
			sprintf(head, "HTTP/1.1 400 Bad Request\r\nDate: %s\r\nContent-Length: %ld\r\ncharset=ISO-8859-1\r\n\r\n", d, (long) strlen(response));
			write(descriptorFichero, head, strlen(head));
			write(descriptorFichero, response, strlen(response));
			close(descriptorFichero);
			debug(ERROR,"400", "Bad Request", descriptorFichero);
		}
		char *p;
		//Deny access to parent directories
		if (p = strstr (dir,"..")){
			char head[200];
			char d[1000];
			time_t now = time(0);
			struct tm tm = *gmtime(&now);
			strftime(d, sizeof d, "%a, %d %b %Y %H:%M:%S %Z", &tm);
			char response[BUFSIZE];
			sprintf(response, "<head><title>Error page</title><h1>ERROR 403: Forbidden.</br></h1></head><body>Requeste file or directory is forbidden.</body>");
			sprintf(head, "HTTP/1.1 403 Forbidden\r\nDate: %s\r\nContent-Length: %ld\r\ncharset=ISO-8859-1\r\n\r\n", d, (long) strlen(response));
			write(descriptorFichero, head, strlen(head));
			write(descriptorFichero, response, strlen(response));
			close(descriptorFichero);
			debug(ERROR,"403", "Forbidden", descriptorFichero);
		}
		if (strcmp(dir, "/") == 0) dir = "/index.html";
		//Check the file extension
		char *fileext = get_filename_ext(dir);
		int i = 0;
		int supported = 0;
		while (extensions[i].ext != NULL){
			if (strcmp(extensions[i].ext,fileext)== 0){
				ext = extensions[i].filetype;
				supported = 1;
			}
			i++;
		}
		if (!supported){			
			char head[200];
			char d[1000];
			time_t now = time(0);
			struct tm tm = *gmtime(&now);
			strftime(d, sizeof d, "%a, %d %b %Y %H:%M:%S %Z", &tm);
			char response[BUFSIZE];
			sprintf(response, "<head><title>Error page</title><h1>ERROR 415: Unsupported Media Type.</br></h1></head><body>The file type requested is not supported by the server.</body>");
			sprintf(head, "HTTP/1.1 415 Unsupported Media Type\r\nDate: %s\r\nContent-Length: %ld\r\ncharset=ISO-8859-1\r\n\r\n", d, (long) strlen(response));
			write(descriptorFichero, head, strlen(head));
			write(descriptorFichero, response, strlen(response));
			close(descriptorFichero);
			debug(ERROR,"415", "Unsupported Media Type", descriptorFichero);
		}
	} else {
		char head[200];
		char d[1000];
		time_t now = time(0);
		struct tm tm = *gmtime(&now);
		strftime(d, sizeof d, "%a, %d %b %Y %H:%M:%S %Z", &tm);
		char response[BUFSIZE];
		sprintf(response, "<head><title>Error page</title><h1>ERROR 405: Method Not Allowed.</br></h1></head><body>Method used not supported by the server. If you think it should be, notify the server administrator.</body>");
		sprintf(head, "HTTP/1.1 405 Method Not Allowed\r\nDate: %s\r\nContent-Length: %ld\r\ncharset=ISO-8859-1\r\n\r\n", d, (long) strlen(response));
		write(descriptorFichero, head, strlen(head));
		write(descriptorFichero, response, strlen(response));
		close(descriptorFichero);
		debug(ERROR,"405", "Method Not Allowed", descriptorFichero);
	}
	line = strtok(NULL , "\r\n");
	//Get all lines and act accordingly
	while (line != NULL){
		op = strsep(&line," ");
		if (strcmp(op, "Host:") == 0){
			host = strsep(&line," ");
		}
		else if (strcmp(op, "User-Agent:") == 0){
			useragent = strsep(&line," ");
		}
		else if (strcmp(op, "Accept:") == 0){
			acc = strsep(&line," ");
		}
		else if (strcmp(op, "Accept-Languaje:") == 0){
			lang = strsep(&line," ");
		}
		else if (strcmp(op, "Accept-Encoding:") == 0){
			enc = strsep(&line," ");
		}
		else if (strcmp(op, "Upgrade-Insecure-Requests:") == 0){
			uir = strsep(&line," ");
		}
		else if (strcmp(op, "Referer:") == 0){
			ref = strsep(&line," ");
		}
		else if (strcmp(op, "Accept-Charset:") == 0){
			chset = strsep(&line," ");
		}
		else if (strcmp(op, "Keep-Alive:") == 0){
			ka = strsep(&line," ");
		}
		else if (strcmp(op, "If-Modified-Since:") == 0){
			ims = strsep(&line," ");
		}
		else if (strcmp(op, "Connection:") == 0){
			con = strsep(&line," ");
		}
		else if (strcmp(op, "Date:") == 0){
			date = strsep(&line," ");
		}
		else if (strcmp(op, "Cache-Control:") == 0){
			cc = strsep(&line," ");
		}
		else if (strcmp(op, "Cookie:") == 0){
			if (strcmp(strsep(&line,"="), "cookie_counter") == 0){
				cookie = atoi(line);
				if (cookie >= 50){
					char head[200];
					char d[1000];
					time_t now = time(0);
					struct tm tm = *gmtime(&now);
					strftime(d, sizeof d, "%a, %d %b %Y %H:%M:%S %Z", &tm);
					char response[BUFSIZE];
					sprintf(response, "<head><title>Error page</title><h1>ERROR 403: Forbidden.</br></h1></head><body>Server rejected the conection.</body>");
					sprintf(head, "HTTP/1.1 403 Forbidden\r\nDate: %s\r\nContent-Length: %ld\r\ncharset=ISO-8859-1\r\n\r\n", d, (long) strlen(response));
					write(descriptorFichero, head, strlen(head));
					write(descriptorFichero, response, strlen(response));
					close(descriptorFichero);
					debug(ERROR,"403", "Forbidden", descriptorFichero);
				}
				cookie++;
			}
		}
		line = strtok(NULL , "\r\n");
	}
	//Check if file can be opened
	if ((fd = open(dir+1, O_RDONLY)) == -1){
		char head[200];
		char d[1000];
		time_t now = time(0);
		struct tm tm = *gmtime(&now);
		strftime(d, sizeof d, "%a, %d %b %Y %H:%M:%S %Z", &tm);
		char response[BUFSIZE];
		sprintf(response, "<head><title>Error page</title><h1>ERROR 404: File not Found.</br></h1></head><body>The file requested couldn't be found in the server files.</body>");
		sprintf(head, "HTTP/1.1 404 File Not Found\r\nDate: %s\r\nContent-Length: %ld\r\ncharset=ISO-8859-1\r\n\r\n", d, (long) strlen(response));
		write(descriptorFichero, head, strlen(head));
		write(descriptorFichero, response, strlen(response));
		close(descriptorFichero);
		debug(ERROR,"404", "File Not Found", descriptorFichero);
	}
	else{
		char d[1000];
		time_t now = time(0);
		struct tm tm = *gmtime(&now);
		strftime(d, sizeof d, "%a, %d %b %Y %H:%M:%S %Z", &tm);

		char head[200];
		sprintf(head, "HTTP/1.1 200 OK\r\nDate: %s\r\nContent-Length: %d\r\nContent-Type: %s; charset=ISO-8859-1\r\nSet-Cookie: cookie_counter=%d; Max-Age=120\r\nServer: sstt8416.org\r\n\r\n", d, filesize(dir),ext,cookie);
		write(descriptorFichero, head, strlen(head));
		int mbytes = 0;
		while (filesize(dir) > mbytes){
			int readbytes = read(fd, buf2, BUFSIZE);
			mbytes += readbytes;
			int obytes = 0;
			while (readbytes > obytes){
				int readbytes2 = write(descriptorFichero, buf2, readbytes);
				obytes += readbytes2;
			}
		}
	}
	
	/*
	The file descriptor will be closed when the conexion expires, not here.
	
	close(descriptorFichero);
	exit(1);
	*/
}

int help() {
   printf("Usage: web_sstt [-i] [-s]\n");
   printf("\t-i: an integer\t[server port]\n");
   printf("\t-s: a string\t[directory where the server files are located]\n");
   return 1;
}

int main(int argc, char **argv)
{
	int i, port, pid, listenfd, socketfd;
	socklen_t length;
	static struct sockaddr_in cli_addr;		// static = Inicializado con ceros
	static struct sockaddr_in serv_addr;	// static = Inicializado con ceros
	
	//Args testing
	
	//Check number of given args
	if (argc < REQUIRED_ARGS){
		printf("Wrong number of arguments.\n");
		help();
		exit(4);
	}
	//Check directory
	DIR* dir = opendir(argv[2]);
	if (dir) {
		closedir(dir);
	} else if (ENOENT == errno){
		printf("Directory passed as argument does not exist.\n");
		help();
		exit(4);
	} else {
		printf("You don't have permission to open the directory passed as argument.\n");
		help();
		exit(4);
	}

	if(chdir(argv[2]) == -1){ 
		(void)printf("ERROR: No se puede cambiar de directorio %s\n",argv[2]);
		exit(4);
	}
	// Hacemos que el proceso sea un demonio sin hijos zombies
	if(fork() != 0)
		return 0; // El proceso padre devuelve un OK al shell

	(void)signal(SIGCHLD, SIG_IGN); // Ignoramos a los hijos
	(void)signal(SIGHUP, SIG_IGN); // Ignoramos cuelgues
	
	debug(LOG,"web server starting...", argv[1] ,getpid());
	
	/* setup the network socket */
	if((listenfd = socket(AF_INET, SOCK_STREAM,0)) <0)
		debug(ERROR, "system call","socket",0);
	
	port = atoi(argv[1]);
	
	if(port < 0 || port >60000)
		debug(ERROR,"Puerto invalido, prueba un puerto de 1 a 60000",argv[1],0);
	
	/*Se crea una estructura para la información IP y puerto donde escucha el servidor*/
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); /*Escucha en cualquier IP disponible*/
	serv_addr.sin_port = htons(port); /*... en el puerto port especificado como parámetro*/
	
	if(bind(listenfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr)) <0)
		debug(ERROR,"system call","bind",0);
	
	if( listen(listenfd,64) <0)
		debug(ERROR,"system call","listen",0);
	
	while(1){
		length = sizeof(cli_addr);
		if((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0)
			debug(ERROR,"system call","accept",0);
		if((pid = fork()) < 0) {
			debug(ERROR,"system call","fork",0);
		}
		else {
			if(pid == 0) {
				(void)close(listenfd);
			
				//Persistence
				fd_set rfds;
				struct timeval tv;
				int retval;
			
				FD_ZERO(&rfds);
				FD_SET(socketfd,&rfds);
				//wait (TIMEOUT) time
				tv.tv_sec = TIMEOUT;
				tv.tv_usec = 0;
				
				while(retval = select(socketfd+1,&rfds, NULL, NULL, &tv)){
					tv.tv_sec = TIMEOUT;
					//exit when no data is available
					if (retval == -1) break;
					else {
						debug(LOG,"connection_status","Data is ready.",socketfd);
						process_web_request(socketfd);
					}
				}
				//When TIMEOUT is reached the conexion will close
				debug(LOG,"connection_status","Data expired: TIMEOUT value reached.",socketfd);
				close(socketfd);
				exit(0);
			} else {
				(void)close(socketfd);
			}
		}
	}
}
