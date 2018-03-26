#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define ERR_MSG "/dev/encrypt isn't open.\nOr try chmod 666 /dev/encrypt"
#define ERR 1
#define BUF_LEN 256
#define end_mess "Aleksa Arsic (RA119/2015) 2018"
#define MANUAL 1
#define F_READ 2
#define ENCRYPT 1
#define DECRYPT 2
#define SEED_LEN 11


/* Global variables */
char buf[BUF_LEN];
int seed = 1;
int public_key = 0;

/* Methods */ 
int start_menu();
int data_entry();
void confirmation(int *conf);
int manual_entry(char buffer[]);
int file_entry(char buffer[]);
int	request_p_key();
int make_buf(const int opt, const char buffer[]);
void remove_p_key(char buffer[]);
void put_p_key_in_file(char p_key);

int main() {

	int file_desc;
	int ret_val;
	int st_menu_opt = 0;
	int data_ent_opt = 0;
	char buffer[BUF_LEN];
	char p_key = '0';

	/* Open the device */
	file_desc = open("/dev/encrypt", O_RDWR);

	if(file_desc < 0){
		puts("****************************************");
		puts(ERR_MSG);
		puts("****************************************");
		return -ERR;
	}

	/* Get ENCRYPT or DECRYPT option from user */
	do{
		st_menu_opt = start_menu();
	}while(st_menu_opt < 1 || st_menu_opt > 2);

	/* Get MANUAL or F_READ option from user */
	do{
		data_ent_opt = data_entry();
	}while(data_ent_opt < 1 || data_ent_opt > 2);

	memset(buffer,'\0', BUF_LEN);
	/* Switch between Manual anf file data entry */
	switch(data_ent_opt){
		case MANUAL:
			manual_entry(buffer);
			break;
		case F_READ:
			file_entry(buffer);
			break;
		default:
			puts("Oops! Something went wrong.\n");
			puts(end_mess);
			return -1;
	}

	/* Generate seed for ENCRYPT option */	
	if(st_menu_opt == ENCRYPT){										   
		seed = time(NULL)%999999999; /* Result will always be less than 10 000 000 */
		printf("Seed: %d\n", seed);
	}

	/* Request public key from user */
	if(st_menu_opt == DECRYPT){
		request_p_key();
	}

	/* Prepare buffer to send to kernel space */
	if(!(make_buf(st_menu_opt, buffer))){
		puts("****************************************");
		puts("Everything ok.");
	}else return -ERR;

	/* Writes to kernel space */
    ret_val = write(file_desc, buf, strlen(buf));
    printf("Data for processing: %s\n", buf);

	/*Reads from kernel space */
	memset(buf, '\0', BUF_LEN);
    ret_val = read(file_desc, buf, strlen(buf));
    printf("Processed data: %s\n", buf);

	/* Writes result in file */
	FILE *fp = fopen("./data/result.txt", "w");

	/*Removes unnecessary data from the buffer */
	if(st_menu_opt == ENCRYPT){
		/* Get public key from buffer */	
		p_key = buf[0];
		printf("Your unique public key: %d\n", p_key);
		remove_p_key(buf);
	}
	
	fputs(buf, fp);
	puts("Processed data can be found at ./data/result.txt");
	
	fclose(fp);

	if(st_menu_opt == ENCRYPT)
		put_p_key_in_file(p_key);

	close(file_desc);
	
	return 0;

}

/* Returns value of start menu option */
int start_menu(){

	int retVal = 0;

	puts("****************************************");
	puts("Test app for encryption kernel module.");
	puts("****************************************");
	puts("1. Encrypt data");
	puts("2. Decrypt data");
	puts("****************************************");
	printf("Choose option: ");
	scanf("%d", &retVal);

	return retVal;
}

/* Asks user if he wants to enter his data trough
 * stdin or input file and returns that value
 */
int data_entry(){

	int retVal = 0;

	puts("****************************************");
	puts("*  Data must be without spaces");
	puts("** File must be in working directory and\nnamed data.txt");
	puts("****************************************");

	puts("****************************************");
	puts("1. Enter data manually. *");
	puts("2. Read from file. **");
	puts("****************************************");
	printf("Choose option: ");
	scanf("%d", &retVal);

	return retVal;
}

/* Data entry from stdin */
int manual_entry(char buffer[]){

	puts("****************************************");
	puts("Enter data: ");
	scanf("%s", buffer);

	return 0;
}

/* Data entry from file */
int file_entry(char buffer[]){

	FILE *fp = fopen("./data/data.txt", "r");

	puts("****************************************");
	puts("Data from file data.txt: ");
	while(fgets(buffer, BUF_LEN, fp) != NULL){
		puts(buffer);
	}

	fclose(fp);
	return 0;
}

int	request_p_key(){

	puts("****************************************");
	puts("Enter your unique public key: ");
	scanf("%d", &public_key);

	return 0;	
}

int make_buf(const int opt, const char buffer[]){

	char s[SEED_LEN];
	char pb_k[3];

	memset(s, '\0', SEED_LEN);
	memset(buf, '\0', BUF_LEN);

	switch(opt){
		case ENCRYPT:
			sprintf(s, "%d", seed);
			buf[0] = opt + '0';
			buf[1] = '|';
			strcat(buf, s);			
			strcat(buf, "|");			
			strcat(buf, buffer);	
			break;
		case DECRYPT:
			sprintf(pb_k, "%c", public_key);
			buf[0] = opt + '0';
			buf[1] = '|';
			strcat(buf, pb_k);			
			strcat(buf, "|");			
			strcat(buf, buffer);	
			break;
		default:
			puts("Oops! Something went wrong.\n");
			puts(end_mess);
			return -1;
	}

	return 0;
}

void remove_p_key(char buffer[]){
	
	int i;
	
	for(i = 0; i < strlen(buffer); i++){
		buffer[i] = buffer[i + 2];
	}
	buffer[i] = '\0';
}

void put_p_key_in_file(char p_key){
			
	char *msg = "\nYour unique public key: ";		
	char key[BUF_LEN];
	FILE *fp = fopen("./data/result.txt", "a");
	
	sprintf(key, "%d", p_key);
	fputs(msg, fp);
	fputs(key, fp);

	fclose(fp);
}
