#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

#define BUF_LEN 256
#define KEY_LEN 8
#define DEVICE_NAME "encrypt"
#define SUCCESS 0
#define ERROR 1
#define ENCRYPT '1'
#define DECRYPT '2'
#define ENC 1
#define DEC 2
#define SEED_DESC "Seed for generating secret key."


/* Declaration of encrypt.c functions */
void encrypt_exit(void);
int encrypt_init(void);
static int encrypt_open(struct inode *, struct file *);
static int encrypt_release(struct inode *, struct file *);
static ssize_t encrypt_read(struct file *, char *buf, size_t , loff_t *);
static ssize_t encrypt_write(struct file *, const char *buf, size_t , loff_t *);

/* Structure that declares the usual file access functions. */
struct file_operations encrypt_fops =
{
    read    :   encrypt_read,
    write   :   encrypt_write,
    open    :   encrypt_open,
    release :   encrypt_release
};

/* Declaration of the init and exit functions. */
module_init(encrypt_init);
module_exit(encrypt_exit);

/* Global variables of the driver */

/* Major number */
static int major;
/* Device open (1 -> true)(0 -> false) */
/* Used to prevent multiple access to device. */
static int Device_Open = 0;
/* Buffer to store data. */
static unsigned char buffer[BUF_LEN];
char *buf_ptr;
/* Seed parameter */
static int seed = 1;
static int p_seed = 1;
/* Secret/private key */
unsigned char s_key = '0';
/* Public key */
unsigned char p_key = '0';
unsigned char **p_key_endptr;
/* Unique key - generated from secret/private key and public key */
char unsigned u_key[KEY_LEN];
/* Option from user space */
int option;

/*
* module_param(variable_name, data_type, 0000)
* The first param is the parameters name.
* The second param is it's data type.
* The final argument is the permissions bits.
*/
module_param(seed, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(seed, SEED_DESC);

/*
 * Pseudorandom number generator
 * Returns unsigned char 
 */
static unsigned char prng(const int seed){
	
	unsigned int retVal = 0;

	retVal = (56984671 * seed) + 91563437;
	retVal %= 126;

	/* First 32 chars in ASCII are not symbols */
	if(retVal <= 32) retVal += 33;
	return retVal; 
}

/*
 * Pseudorandom number generator
 * Fills u_key (unique key) buffer with pseudo-random numbers derived from 
 * secret key (s_key) and public key (p_key)
 */
static void unique_key(const int s_key, const int p_key){
	
    int i = 0;
	for(i = 0; i < KEY_LEN; i++){
        u_key[i] = (141996333 * s_key) + (211219983 * p_key) + 262970333;
        u_key[i] += i * 51512;
        u_key[i] %= 126;

		/* First 32 chars in ASCII are not symbols */
        if(u_key[i] <= 32) u_key[i] += 33;
    }
}

/* KERNEL MODUL LOGIC
 * XOR-s data from buffer with unique key 
 * First 31 characters in ASCII table are ignored 
 * Individual chars after encryption or decryption are in range (31, 255]
 * If user chose to encrypt data we will xor the pair (data, u_key) and 
 * check if the xor result is less than 32 if it is then as the result we will
 * give second time xor-ed pair (data, u_key) wich is the original data 
 * Same is done for decryption and if the xor-ed pair (data, u_key) are less then 32
 * we will xor it again and get original data.
 * We circulate u_key buffer and xor whole data with repeated unique key
 */
static int xor_data(void){

	int i;
	unsigned char temp = 0;

	/* Generate unique key from secret/private key 
	 * and public key 
	 */		
	unique_key(s_key, p_key);
	printk(KERN_INFO "Unique key for encrypt/decrypt: %s\n", u_key);

	for(i = 0; i < strlen(buffer); i++){

		if((buffer[i] == '\n') || (buffer[i] == '\0')) break;

		temp = buffer[i];
		temp ^= u_key[i % KEY_LEN];
		if(temp < 32) temp ^= u_key[i % KEY_LEN];
        buffer[i] = temp;
	}
	
	printk(KERN_INFO "Result of xor: %s\n", buffer);
	return SUCCESS;
}


/* Parse buffer if user chose to decrypt data. */
static int parse_buf_dec(char buffer[]){

    char temp[BUF_LEN];
    int i;
    int k = 0;

    memset(temp, '\0', BUF_LEN);

	/* Get option from buffer (ENCRYPT or DECRYPT) */
    option = buffer[0] - '0';
	printk(KERN_INFO "Option: %d", option);

	/* Get public key from buffer */
	p_key = buffer[2];
    printk(KERN_INFO "Public key char: %c\n", p_key);

    memset(temp, '\0', BUF_LEN);

	/* Get data from buffer */
    for(i = 4; i < strlen(buffer); i++, k++){
		if(buffer[i] == '\n') break;
        temp[k] = buffer[i];
    }

    memset(buffer, '\0', BUF_LEN);
	strcpy(buffer, temp);
    printk(KERN_INFO "Data: %s", buffer);

    return SUCCESS;
}


/* Parse buffer if user chose to encrypt data. */
static int parse_buf_enc(char buffer[]){

	char temp[BUF_LEN];
	char **temp_end;
    int i;
    int j = 0;
	int k = 0;

    memset(temp, '\0', BUF_LEN);

	/* Get option from buffer (ENCRYPT or DECRYPT) */
    option = buffer[0] - '0';
	printk(KERN_INFO "Option: %d", option);

	/* Get seed from buffer for generating public key */
    for(i = 2; i < strlen(buffer); i++){
		if(buffer[i] == '|'){
			j = i;
			break;
		}
		temp[i - 2] = buffer[i];
	}
	p_seed = simple_strtol(temp, temp_end, 10); 
	printk(KERN_INFO "P_SEED: %d\n", p_seed);
	
	/* Get data from buffer (for ENCRYPT or DECRYPT) */
    memset(temp, '\0', BUF_LEN);
	for(i = j + 1; i < strlen(buffer); i++, k++){
		if(buffer[i] == '\0') break;
		temp[k] = buffer[i];
	}
	temp[strlen(temp)] = '\0';
    memset(buffer, '\0', BUF_LEN);
	strcpy(buffer, temp);
	printk(KERN_INFO "Data: %s\n", buffer);

	/* Generate public key */
	p_key = prng(p_seed);
	printk(KERN_INFO "Public key: %d", p_key);

    return SUCCESS;
}

/* Generating end buffer that will be sent to the user space
 * after module is finished processing data
 */
static int generate_end_buffer(void){
	char temp[BUF_LEN];	
	int i;

	memset(temp, '\0', BUF_LEN);
	strcpy(temp, buffer);
	memset(buffer, '\0', BUF_LEN);

	if(option == 1){
		buffer[0] = p_key;
		buffer[1] = '|';
		strcat(buffer, temp);
	}else if(option == 2){
		for(i = 0; i < strlen(temp); i++) buffer[i] = temp[i];
	}else{
		printk(KERN_INFO "Oops! Something went wrong.\n");
		return -ERROR;
	}

	buffer[strlen(buffer)] = '\0';
	printk(KERN_INFO "Buffer after xor: %s\n", buffer);
	return SUCCESS;
}

/*
 * Initialization:
 *  1. Register device driver
 *  2. Allocate buffer
 *  3. Initialize buffer
 *  4. Generate secret key
 */
int encrypt_init(void) {

	int result;

    /* Registering device. */
    major = register_chrdev(0, DEVICE_NAME, &encrypt_fops);
    if(major < 0) {
        printk(KERN_INFO "encrypt: cannot obtain major number %d\n", major);
        return major;
    }

	printk(KERN_INFO "encrypt assigned to major number: %d\n", major);
    /* Allocating memory for the buffer. */
    buf_ptr = kmalloc(BUF_LEN, GFP_KERNEL);
    if(!buf_ptr) {
        result = -ENOMEM;
        goto fail;
    }

    memset(buffer, 0, BUF_LEN);
    printk(KERN_INFO "Inserting encrypt module\n");
	printk(KERN_INFO "Seed for generating secret key: %d\n", seed);

	s_key = prng(seed);
	printk(KERN_INFO "Secret key: %d\n", s_key);

    return 0;

fail:
    encrypt_exit();
    return result;

}

/*
 * Cleanup:
 *  1. Unregister device driver
 *  2. Free buffer
 */
void encrypt_exit(void) {
    
	/* Freeing the major number. */
    unregister_chrdev(major, DEVICE_NAME);

    /* Freeing buffer memory. */
	/* If used kfree(buffer) causes stack overflow and (core dumped)?*/
    //if(buffer) kfree(buffer);

    printk(KERN_INFO "Removing encrypt module\n");

}

/* File open function. */
static int encrypt_open(struct inode *inode, struct file *filp)
{

	if(Device_Open) return -EBUSY;

	Device_Open++;
	sprintf(buffer, "Device opened.\nSecret key: %d\n", s_key);
	buf_ptr = buffer;
	try_module_get(THIS_MODULE);

	return SUCCESS;
}

/* File close function. */
static int encrypt_release(struct inode *inode, struct file *filp)
{
	Device_Open--;  /* We're now ready for our next caller. */

	/*
	* Decrement the usage count, or else once you opened the file, you'll
	* never get get rid of the module.
	*/
	module_put(THIS_MODULE);

    return 0;
}

/*
 * File read function
 *  Parameters:
 *   filp  - a type file structure;
 *   buf   - a buffer, from which the user space function (fread) will read;
 *   len - a counter with the number of bytes to transfer, which has the same
 *           value as the usual counter in the user space function (fread);
 *   f_pos - a position of where to start reading the file;
 *  Operation:
 *   The encrypt_read function transfers data from the driver buffer (buffer)
 *   to user space with the function copy_to_user.
 */
static ssize_t encrypt_read(struct file *filp, char *buf, size_t len, loff_t *f_pos)
{
    /* Size of valid data in memory - data to send in user space. */
    int data_size = 0;

	/* Processing data and generating end buffer for sending 
	 * to user space 	
	 */

	xor_data();
	generate_end_buffer();

    if (*f_pos == 0) {
        /* Get size of valid data. */
        data_size = strlen(buf_ptr);

        /* Send data to user space. */
        if (copy_to_user(buf, buf_ptr, data_size) != 0) {
            return -EFAULT;
        }
        else{
            (*f_pos) += data_size;
			return data_size;
        }
    }
    else return 0;
}

/*
 * File write function
 *  Parameters:
 *   filp  - a type file structure;
 *   buf   - a buffer in which the user space function (fwrite) will write;
 *   len - a counter with the number of bytes to transfer, which has the same
 *           values as the usual counter in the user space function (fwrite);
 *   f_pos - a position of where to start writing in the file;
 *  Operation:
 *   The function copy_from_user transfers the data from user space to kernel space.
 *	 Switch between options from user (ENCRYPT or DECRYPT) and prepare data for processing.
 */
static ssize_t encrypt_write(struct file *filp, const char *buf, size_t len, loff_t *f_pos)
{
    /* Reset memory. */
    memset(buf_ptr, 0, BUF_LEN);

    /* Get data from user space.*/
    if (copy_from_user(buf_ptr, buf, len) != 0) {
        return -EFAULT;
    }
    else{
		/* Preparing data for encrypt/decrypt */
		if(buffer[0] == ENCRYPT){
			parse_buf_enc(buffer);
		}else if(buffer[0] == DECRYPT){
			parse_buf_dec(buffer);
		}else{
			return -ERROR;
		}

		return len;
	}
}
