#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

/* If you want debugging output, use the following macro.
 * When you hand in, remove the #define DEBUG line. */
// #define DEBUG
#ifdef DEBUG
#define debug(fmt, ...) printf("%s: " fmt "\n", __func__, __VA_ARGS__)
#define msg(...) printf(__VA_ARGS__)
#else
#define debug(fmt, ...)
#define msg(...)
#endif

#define __unused __attribute__((unused))

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* !DRIVER */

typedef int32_t word_t; /* Heap is bascially an array of 4-byte words. */

typedef enum
{
  FREE = 0,     /* Block is free */
  USED = 1,     /* Block is used */
  PREVFREE = 2, /* Previous block is free (optimized boundary tags) */
} bt_flags;

static word_t *heap_start; /* Address of the first block */
static word_t *heap_end;   /* Address past last byte of last block */
static word_t *last;       /* Points at last block */

/* --=[ boundary tag handling ]=-------------------------------------------- */

static inline word_t bt_size(word_t *bt)
{
  return *bt & ~(USED | PREVFREE);
}

static inline int bt_used(word_t *bt)
{
  return *bt & USED;
}

static inline int bt_free(word_t *bt)
{
  return !(*bt & USED);
}

/* Given boundary tag address calculate it's buddy address. */
static inline word_t *bt_footer(word_t *bt)
{
  return (void *)bt + bt_size(bt) - sizeof(word_t);
}

/* Given payload pointer returns an address of boundary tag. */
static inline word_t *bt_fromptr(void *ptr)
{
  return (word_t *)ptr - 1;
}

/* Creates boundary tag(s) for given block. */
static inline void bt_make(word_t *bt, size_t size, bt_flags flags)
{
  (*bt) = size | flags;
  (*bt_footer(bt)) = size | flags;
}

/* Previous block free flag handling for optimized boundary tags. */
static inline bt_flags bt_get_prevfree(word_t *bt)
{
  return *bt & PREVFREE;
}

static inline void bt_clr_prevfree(word_t *bt)
{
  if (bt)
    *bt &= ~PREVFREE;
}

static inline void bt_set_prevfree(word_t *bt)
{
  *bt |= PREVFREE;
}

/* Returns address of payload. */
static inline void *bt_payload(word_t *bt)
{
  return bt + 1;
}

/* Returns address of next block or NULL. */
static inline word_t *bt_next(word_t *bt)
{
  if (bt == last)
    return NULL;
  return (void *)bt + bt_size(bt);
}

/* Returns address of previous block or NULL. */
static inline word_t *bt_prev(word_t *bt)
{
  if (heap_start == bt)
    return NULL;
  word_t *prevfooter = bt - 1;
  void *prevheader = (void *)prevfooter - bt_size(prevfooter) + sizeof(word_t);
  return prevheader;
}

/* --=[ miscellanous procedures ]=------------------------------------------ */

/* Calculates block size incl. header, footer & payload,
 * and aligns it to block boundary (ALIGNMENT). */
static inline size_t blksz(size_t size)
{
  size_t payload_and_footer = size + sizeof(word_t);
  if (payload_and_footer % ALIGNMENT == 0)
    return payload_and_footer + ALIGNMENT; //header + payload + footer + padding (wielkosci aligmnent minus jedno slowo)
  else if (payload_and_footer % ALIGNMENT == ALIGNMENT - sizeof(word_t))
    return sizeof(word_t) + payload_and_footer; //header + payload + footer
  else
    return sizeof(word_t) + payload_and_footer + ALIGNMENT - payload_and_footer % ALIGNMENT - sizeof(word_t);
}

static void *morecore(size_t size)
{
  void *ptr = mem_sbrk(size);
  if (ptr == (void *)-1)
    return NULL;
  return ptr;
}

/* --=[ mm_init ]=---------------------------------------------------------- */

int mm_init(void)
{
  void *ptr = morecore(ALIGNMENT - sizeof(word_t));
  if (!ptr)
    return -1;
  heap_start = NULL;
  heap_end = NULL;
  last = NULL;
  return 0;
}

/* --=[ malloc ]=----------------------------------------------------------- */

#if 1
/* First fit startegy. */
static word_t *find_fit(size_t reqsz)
{
  if (!heap_start)
    return NULL;
  word_t *pointer = heap_start;
  while (1)
  {
    if (bt_free(pointer))
    {
      if (bt_size(pointer) >= reqsz)
        return pointer;
    }
    pointer = bt_next(pointer);
    if (!pointer)
      return NULL;
  }
}
#else
/* Best fit startegy. */
static word_t *find_fit(size_t reqsz)
{
}
#endif

void *malloc(size_t size)
{
  size_t blocksize = blksz(size);
  word_t *pointer = find_fit(blocksize);
  if (pointer == NULL)
  {
    pointer = mem_sbrk(blocksize);
    if ((long)pointer < 0)
      return NULL;
    if (!heap_start)
      heap_start = pointer;
    last = pointer;
    heap_end = (void *)pointer + blocksize;
  }
  else // pointer!=NULL
  {
    size_t nonused = bt_size(pointer) - blocksize;
    if (nonused < ALIGNMENT + sizeof(word_t))
    {
      (*pointer) = blocksize | USED;
      (*bt_footer(pointer)) = (*pointer);
    }
    else
    {
    }
  }
  return pointer + 1;
}

/* --=[ free ]=------------------------------------------------------------- */

void free(void *ptr)
{
}

/* --=[ realloc ]=---------------------------------------------------------- */

void *realloc(void *old_ptr, size_t size)
{
}

/* --=[ calloc ]=----------------------------------------------------------- */

void *calloc(size_t nmemb, size_t size)
{
  size_t bytes = nmemb * size;
  void *new_ptr = malloc(bytes);
  if (new_ptr)
    memset(new_ptr, 0, bytes);
  return new_ptr;
}

/* --=[ mm_checkheap ]=----------------------------------------------------- */

void mm_checkheap(int verbose)
{
}
