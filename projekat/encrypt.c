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

#define BUF_LEN 128
#define DEVICE_NAME "encrypt"
#define SUCCESS 0
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
static int Device_Open = 0;
/* Used to prevent multiple access to device. */
static char buffer[BUF_LEN];
/* Buffer to store data. */
char *buf_ptr;
/* Seed parameter */
static int seed = 1;
/* Secrete key */
unsigned char s_key = '0';


/*
* module_param(variable_name, data_type, 0000)
* The first param is the parameters name.
* The second param is it's data type.
* The final argument is the permissions bits.
*/
module_param(seed, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(seed, SEED_DESC);

/*
 * Pseudo random generator
 * Returns unsigned char 
 */
static unsigned char prng(const int seed){
	
	unsigned char retVal = '0';

	retVal = (56984671 * seed) + 91563437;

	return retVal % 255; 
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
	printk(KERN_INFO "Secret key: %d", s_key);

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
    //if(buffer) kfree(buffer);

    printk(KERN_INFO "Removing encrypt module\n");

}

/* File open function. */
static int encrypt_open(struct inode *inode, struct file *filp)
{

	if (Device_Open) return -EBUSY;

	Device_Open++;
	sprintf(buffer, "Device already opened.\nSecret key: %d\n", s_key);
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

	/* TO-DO: Fill buffer with data from user space */

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
		/* TO-DO: add parsing and encrypt/decrypt options */
		return len;
	}
}
