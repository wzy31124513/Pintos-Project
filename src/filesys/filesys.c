#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);
static bool name2entry(const char *name,struct dir **dir, char name[15]);
static int get_next_part (char *name, const char **srcp);
/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  cache_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  cache_flush ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool directory) 
{
  struct dir *dir;
  char base_name[15];
  block_sector_t inode_sector;

  bool success = (name2entry (name, &dir, base_name) && free_map_allocate (&inode_sector));
  if (success) 
  {
    struct inode *inode;
    if (!directory){
      inode = file_create(inode_sector,initial_size);
    }else{
          inode = dir_create(inode_sector,inode_get_inumber(dir_get_inode(dir))); 
    }
    if (inode != NULL)
    {
      success = dir_add(dir, base_name, inode_sector);
       if (!success){
        inode_remove(inode);
       }
      inode_close(inode);
    }else{
      success = false;
    }
  }
  dir_close (dir);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct inode *
filesys_open (const char *name)
{
  if (name[0]=='/' && name[strspn(name, "/")]=='\0') 
  {
    return inode_open (ROOT_DIR_SECTOR);
  }else {
    struct dir *dir;
    char base_name[15];
    if(name2entry(name, &dir, base_name)) 
    {
      struct inode *inode;
      dir_lookup (dir, base_name, &inode);
      dir_close (dir);
      return inode; 
    }else{
      return NULL;
    }
  }
}

static bool name2entry (const char *name,struct dir **dir, char base_name[15]) 
{
  struct dir* d;
  struct inode* inode;
  const char* cp;
  char name1[15],next[15];
  int a;
  if (name[0]=='/'|| thread_current()->wd==NULL)
  {
    d=dir_open_root();
  }else{
    d=dir_reopen(thread_current()->wd);
  }

  if (d==NULL)
  {
    dir_close(d);
    *dir=NULL;
    base_name[0]='\0';
    return false;
  }
  cp=name;
  if (get_next_part(name1,&cp)<=0)
  {
    dir_close(d);
    *dir=NULL;
    base_name[0]='\0';
    return false;
  }
  while((a=get_next_part(next,&cp))>0){
    if (!dir_lookup(d,name1,&inode))
    {
      dir_close(d);
      *dir=NULL;
      base_name[0]='\0';
      return false;
    }
    dir_close(d);
    d=dir_open(inode);
    if (d==NULL)
    {
      dir_close(d);
      *dir=NULL;
      base_name[0]='\0';
      return false;
    }
    strlcpy(name1,next,15);
  }
  if (a<0)
  {
    dir_close(d);
    *dir=NULL;
    base_name[0]='\0';
    return false;
  }
  *dir=d;
  strlcpy(base_name,name1,15);
  return true;
}

static int get_next_part (char part[NAME_MAX], const char **srcp)
{
  const char *src = *srcp;
  char *dst = part;

  /* Skip leading slashes.
     If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.
     Add null terminator. */
  while (*src != '/' && *src != '\0') 
    {
      if (dst < part + NAME_MAX)
        *dst++ = *src;
      else
        return -1;
      src++; 
    }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct dir *dir;
  char base_name[NAME_MAX + 1];
  bool success;

  if (name2entry (name, &dir, base_name)) 
    {
      success = dir_remove (dir, base_name);
      dir_close (dir);
    }
  else
    success = false;
  
  return success;
}


/* Formats the file system. */
static void
do_format (void)
{
  struct inode *inode;
  printf ("Formatting file system...");

  /* Set up free map. */
  free_map_create ();

  /* Set up root directory. */
  inode = dir_create (ROOT_DIR_SECTOR, ROOT_DIR_SECTOR);
  if (inode == NULL)
    PANIC ("root directory creation failed");
  inode_close (inode);  

  free_map_close ();

  printf ("done.\n");
}
